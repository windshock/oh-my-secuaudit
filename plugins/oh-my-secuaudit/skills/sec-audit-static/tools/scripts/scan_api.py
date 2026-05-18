#!/usr/bin/env python3
"""
API 엔드포인트 인벤토리 자동 추출 스크립트

소스코드에서 Spring MVC/WebFlux 컨트롤러를 파싱하여
모든 API 엔드포인트, HTTP 메서드, 파라미터, 인증 여부 등을 추출합니다.

사용법:
    python scan_api.py <source_dir> [--output <file>]
    python scan_api.py testbed/3-pcona/pcona-env-dev@afd19907e2c/
    python scan_api.py testbed/3-pcona/pcona-env-dev@afd19907e2c/ --output state/pcona_api_inventory.json

출력 필드:
    - method: HTTP 메서드 (GET, POST, PUT, DELETE, PATCH)
    - api: 엔드포인트 경로
    - auth_required: 인증 필요 여부
    - handler: 핸들러 (클래스.메서드())
    - file: 소스 파일 경로:라인
    - description: 설명
    - parameters: 전체 파라미터 목록
"""

import json
import os
import re
import sys
import argparse
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


# ============================================================
#  어노테이션 파싱 유틸리티
# ============================================================

def extract_annotation_value(text: str, anno_name: str) -> Optional[str]:
    """어노테이션의 전체 내용을 추출 (괄호 매칭)
    예: @GetMapping("/api/test") -> "/api/test"
    예: @PreAuthorize("hasAnyAuthority('ADMIN')") -> "hasAnyAuthority('ADMIN')"
    """
    pattern = rf'@{anno_name}\s*\('
    match = re.search(pattern, text)
    if not match:
        return None

    start = match.end()
    depth = 1
    i = start
    while i < len(text) and depth > 0:
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
        i += 1

    if depth == 0:
        return text[start:i - 1].strip()
    return None


def extract_paths_from_annotation(anno_content: str) -> list[str]:
    """어노테이션 내용에서 경로 목록을 추출
    예: '"/api"' -> ["/api"]
    예: 'path = ["/req", "/ads"]' -> ["/req", "/ads"]
    예: 'value = ["/req"]' -> ["/req"]
    예: '' -> [""]
    """
    if not anno_content:
        return [""]

    # path = [...] 또는 value = [...] 형태
    list_match = re.search(r'(?:path|value)\s*=\s*\[([^\]]*)\]', anno_content)
    if list_match:
        items = re.findall(r'"([^"]*)"', list_match.group(1))
        return items if items else [""]

    # 단순 문자열 형태: "/path" 또는 value="/path"
    str_match = re.search(r'(?:value\s*=\s*)?["\']([^"\']*)["\']', anno_content)
    if str_match:
        return [str_match.group(1)]

    return [""]


def extract_method_from_request_mapping(anno_content: str) -> list[str]:
    """@RequestMapping의 method 속성에서 HTTP 메서드 추출
    예: 'method = [RequestMethod.GET]' -> ['GET']
    예: 'method = RequestMethod.POST' -> ['POST']
    """
    method_match = re.search(r'method\s*=\s*\[?([^\])\n]*)\]?', anno_content)
    if method_match:
        methods = re.findall(r'RequestMethod\.(\w+)', method_match.group(1))
        return [m.upper() for m in methods] if methods else ["GET"]
    return ["GET"]  # 기본값


def extract_preauthorize(text: str) -> Optional[str]:
    """@PreAuthorize 어노테이션에서 권한 표현식 추출"""
    content = extract_annotation_value(text, 'PreAuthorize')
    if content:
        # 따옴표 제거
        return content.strip('"\'')
    return None


def extract_audit_action(text: str) -> Optional[str]:
    """@PconaAudit(action="...") 에서 action 값 추출"""
    content = extract_annotation_value(text, 'PconaAudit')
    if content:
        action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', content)
        if action_match:
            return action_match.group(1)
    return None


# ============================================================
#  파라미터 파싱
# ============================================================

@dataclass
class Parameter:
    name: str
    type: str  # query, path, body, header, pageable, session, request, response
    data_type: str = ""
    required: bool = True
    default_value: Optional[str] = None


def parse_parameter(param_text: str) -> Optional[Parameter]:
    """함수 파라미터 하나를 파싱
    예: '@RequestParam(value = "search") search: String?'
    예: '@PathVariable(value = "id") id: Long'
    예: '@RequestBody advertiser: Advertiser'
    예: '@PageableDefault(size=10, page=0) page: Pageable'
    예: '@PconaSession user: User'
    예: 'req: ServerHttpRequest'
    """
    param_text = param_text.strip()
    if not param_text:
        return None

    # @RequestParam
    rp_match = re.search(r'@RequestParam\s*(?:\(([^)]*)\))?\s*(\w+)\s*:\s*(\S+)', param_text)
    if rp_match:
        anno_args = rp_match.group(1) or ""
        param_name = rp_match.group(2)
        data_type = rp_match.group(3).rstrip(',')

        # value/name 속성에서 실제 파라미터명 추출
        value_match = re.search(r'(?:value|name)\s*=\s*["\']([^"\']*)["\']', anno_args)
        if value_match:
            param_name = value_match.group(1)

        required = True
        req_match = re.search(r'required\s*=\s*(true|false)', anno_args, re.IGNORECASE)
        if req_match:
            required = req_match.group(1).lower() == 'true'
        elif data_type.endswith('?'):
            required = False

        default = None
        def_match = re.search(r'defaultValue\s*=\s*["\']([^"\']*)["\']', anno_args)
        if def_match:
            default = def_match.group(1)
            required = False

        return Parameter(
            name=param_name, type="query", data_type=data_type,
            required=required, default_value=default
        )

    # @PathVariable
    pv_match = re.search(r'@PathVariable\s*(?:\(([^)]*)\))?\s*(\w+)\s*:\s*(\S+)', param_text)
    if pv_match:
        anno_args = pv_match.group(1) or ""
        param_name = pv_match.group(2)
        data_type = pv_match.group(3).rstrip(',')

        value_match = re.search(r'(?:value|name)\s*=\s*["\']([^"\']*)["\']', anno_args)
        if value_match:
            param_name = value_match.group(1)

        return Parameter(
            name=param_name, type="path", data_type=data_type, required=True
        )

    # @RequestBody
    rb_match = re.search(r'@RequestBody\s*(\w+)\s*:\s*(\S+)', param_text)
    if rb_match:
        return Parameter(
            name=rb_match.group(1), type="body",
            data_type=rb_match.group(2).rstrip(','), required=True
        )

    # @RequestHeader
    rh_match = re.search(r'@RequestHeader\s*(?:\(([^)]*)\))?\s*(\w+)\s*:\s*(\S+)', param_text)
    if rh_match:
        anno_args = rh_match.group(1) or ""
        param_name = rh_match.group(2)
        data_type = rh_match.group(3).rstrip(',')

        value_match = re.search(r'["\']([^"\']*)["\']', anno_args)
        if value_match:
            param_name = value_match.group(1)

        required = not data_type.endswith('?')
        req_match = re.search(r'required\s*=\s*(true|false)', anno_args, re.IGNORECASE)
        if req_match:
            required = req_match.group(1).lower() == 'true'

        return Parameter(
            name=param_name, type="header", data_type=data_type, required=required
        )

    # @PageableDefault (중첩 괄호 지원 - arrayOf() 등)
    if '@PageableDefault' in param_text:
        anno_content = extract_annotation_value(param_text, 'PageableDefault')
        # 어노테이션 끝 이후 변수명:타입 추출
        # @PageableDefault(...) varName: Type 형태
        anno_end = param_text.find('@PageableDefault')
        # 괄호 매칭으로 어노테이션 끝 찾기
        paren_start = param_text.find('(', anno_end)
        if paren_start >= 0:
            depth = 1
            idx = paren_start + 1
            while idx < len(param_text) and depth > 0:
                if param_text[idx] == '(':
                    depth += 1
                elif param_text[idx] == ')':
                    depth -= 1
                idx += 1
            after_anno = param_text[idx:].strip()
        else:
            after_anno = param_text[anno_end + len('@PageableDefault'):].strip()
        var_match = re.search(r'(\w+)\s*:\s*(\S+)', after_anno)
        if var_match:
            return Parameter(
                name=var_match.group(1), type="pageable",
                data_type="Pageable",
                required=False,
                default_value=anno_content.strip() if anno_content else None
            )

    # @PconaSession (custom auth session)
    ps_match = re.search(r'@PconaSession\s*(\w+)\s*:\s*(\S+)', param_text)
    if ps_match:
        return Parameter(
            name=ps_match.group(1), type="session",
            data_type=ps_match.group(2).rstrip(','), required=True
        )

    # @RequestPart (multipart)
    rpart_match = re.search(r'@RequestPart\s*(?:\(([^)]*)\))?\s*(\w+)\s*:\s*(\S+)', param_text)
    if rpart_match:
        anno_args = rpart_match.group(1) or ""
        param_name = rpart_match.group(2)
        value_match = re.search(r'["\']([^"\']*)["\']', anno_args)
        if value_match:
            param_name = value_match.group(1)
        return Parameter(
            name=param_name, type="multipart",
            data_type=rpart_match.group(3).rstrip(','), required=True
        )

    # ServerHttpRequest / ServerHttpResponse (no annotation)
    raw_match = re.search(r'(\w+)\s*:\s*(ServerHttpRequest|ServerHttpResponse|ServerWebExchange)', param_text)
    if raw_match:
        ptype = "request" if "Request" in raw_match.group(2) else "response"
        if "Exchange" in raw_match.group(2):
            ptype = "exchange"
        return Parameter(
            name=raw_match.group(1), type=ptype,
            data_type=raw_match.group(2), required=False
        )

    # @ModelAttribute
    ma_match = re.search(r'@ModelAttribute\s*(?:\(([^)]*)\))?\s*(\w+)\s*:\s*(\S+)', param_text)
    if ma_match:
        return Parameter(
            name=ma_match.group(2), type="model",
            data_type=ma_match.group(3).rstrip(','), required=True
        )

    # Pageable 파라미터 (어노테이션 없이 직접 사용)
    pageable_match = re.search(r'(\w+)\s*:\s*(Pageable)\b', param_text)
    if pageable_match and '@' not in param_text:
        return Parameter(
            name=pageable_match.group(1), type="pageable",
            data_type="Pageable", required=False
        )

    # 일반 파라미터 (어노테이션 없음) - 무시 가능한 타입 필터
    plain_match = re.search(r'(\w+)\s*:\s*(\S+)', param_text)
    if plain_match:
        name = plain_match.group(1)
        dtype = plain_match.group(2).rstrip(',')
        # Spring 내부 객체는 스킵
        skip_types = {
            'BindingResult', 'Errors', 'Model', 'ModelMap',
            'RedirectAttributes', 'SessionStatus', 'UriComponentsBuilder',
        }
        if dtype in skip_types:
            return None
        return Parameter(
            name=name, type="unknown", data_type=dtype, required=False
        )

    return None


def parse_parameter_java(param_text: str) -> Optional[Parameter]:
    """Java 스타일 파라미터 파싱
    예: '@RequestParam("q") String query'
    예: '@PathVariable("id") Long id'
    예: '@RequestBody Foo body'
    """
    param_text = param_text.strip()
    if not param_text:
        return None

    # annotation args
    def _anno_args(name: str) -> Optional[str]:
        return extract_annotation_value(param_text, name)

    # helper: type + name (last token is variable name)
    def _type_and_name() -> Optional[tuple[str, str]]:
        # strip annotations
        cleaned = re.sub(r'@\w+(?:\s*\([^)]*\))?\s*', '', param_text).strip()
        if not cleaned:
            return None
        # split by whitespace, last token is name
        parts = cleaned.split()
        if len(parts) < 2:
            return None
        name = parts[-1]
        dtype = ' '.join(parts[:-1]).rstrip(',')
        return dtype, name

    # @RequestParam
    if '@RequestParam' in param_text:
        anno_args = _anno_args('RequestParam') or ""
        tn = _type_and_name()
        if not tn:
            return None
        dtype, name = tn
        value_match = re.search(r'(?:value|name)\s*=\s*["\']([^"\']*)["\']', anno_args)
        if value_match:
            name = value_match.group(1)
        elif re.search(r'^["\']([^"\']*)["\']$', anno_args.strip()):
            name = re.search(r'^["\']([^"\']*)["\']$', anno_args.strip()).group(1)

        required = True
        req_match = re.search(r'required\s*=\s*(true|false)', anno_args, re.IGNORECASE)
        if req_match:
            required = req_match.group(1).lower() == 'true'
        default = None
        def_match = re.search(r'defaultValue\s*=\s*["\']([^"\']*)["\']', anno_args)
        if def_match:
            default = def_match.group(1)
            required = False

        return Parameter(name=name, type="query", data_type=dtype, required=required, default_value=default)

    # @PathVariable
    if '@PathVariable' in param_text:
        anno_args = _anno_args('PathVariable') or ""
        tn = _type_and_name()
        if not tn:
            return None
        dtype, name = tn
        value_match = re.search(r'(?:value|name)\s*=\s*["\']([^"\']*)["\']', anno_args)
        if value_match:
            name = value_match.group(1)
        elif re.search(r'^["\']([^"\']*)["\']$', anno_args.strip()):
            name = re.search(r'^["\']([^"\']*)["\']$', anno_args.strip()).group(1)
        return Parameter(name=name, type="path", data_type=dtype, required=True)

    # @RequestBody
    if '@RequestBody' in param_text:
        tn = _type_and_name()
        if not tn:
            return None
        dtype, name = tn
        return Parameter(name=name, type="body", data_type=dtype, required=True)

    # @RequestHeader
    if '@RequestHeader' in param_text:
        anno_args = _anno_args('RequestHeader') or ""
        tn = _type_and_name()
        if not tn:
            return None
        dtype, name = tn
        value_match = re.search(r'(?:value|name)\s*=\s*["\']([^"\']*)["\']', anno_args)
        if value_match:
            name = value_match.group(1)
        elif re.search(r'^["\']([^"\']*)["\']$', anno_args.strip()):
            name = re.search(r'^["\']([^"\']*)["\']$', anno_args.strip()).group(1)
        required = True
        req_match = re.search(r'required\s*=\s*(true|false)', anno_args, re.IGNORECASE)
        if req_match:
            required = req_match.group(1).lower() == 'true'
        return Parameter(name=name, type="header", data_type=dtype, required=required)

    # @RequestPart
    if '@RequestPart' in param_text:
        anno_args = _anno_args('RequestPart') or ""
        tn = _type_and_name()
        if not tn:
            return None
        dtype, name = tn
        value_match = re.search(r'(?:value|name)\s*=\s*["\']([^"\']*)["\']', anno_args)
        if value_match:
            name = value_match.group(1)
        elif re.search(r'^["\']([^"\']*)["\']$', anno_args.strip()):
            name = re.search(r'^["\']([^"\']*)["\']$', anno_args.strip()).group(1)
        return Parameter(name=name, type="multipart", data_type=dtype, required=True)

    # @ModelAttribute
    if '@ModelAttribute' in param_text:
        tn = _type_and_name()
        if not tn:
            return None
        dtype, name = tn
        return Parameter(name=name, type="model", data_type=dtype, required=True)

    # unannotated
    tn = _type_and_name()
    if tn:
        dtype, name = tn
        skip_types = {
            'BindingResult', 'Errors', 'Model', 'ModelMap',
            'RedirectAttributes', 'SessionStatus', 'UriComponentsBuilder',
            'HttpServletRequest', 'HttpServletResponse', 'HttpSession',
        }
        if dtype in skip_types:
            return None
        return Parameter(name=name, type="unknown", data_type=dtype, required=False)

    return None


# ============================================================
#  컨트롤러 파싱
# ============================================================

@dataclass
class Endpoint:
    method: str
    api: str
    auth_required: bool
    auth_detail: str
    handler: str
    file: str
    line: int
    module: str
    description: str
    parameters: list
    middleware: list
    return_type: str


# HTTP 메서드 매핑 어노테이션
METHOD_ANNOTATIONS = {
    'GetMapping': 'GET',
    'PostMapping': 'POST',
    'PutMapping': 'PUT',
    'DeleteMapping': 'DELETE',
    'PatchMapping': 'PATCH',
}


def detect_module(filepath: Path, source_dir: Path) -> str:
    """파일 경로에서 모듈명 추출"""
    rel = filepath.relative_to(source_dir)
    parts = rel.parts
    if parts:
        return parts[0]
    return "unknown"


def find_security_configs(source_dir: Path) -> dict[str, dict]:
    """모듈별 보안 설정을 탐색하여 기본 인증 정책 파악"""
    module_auth = {}

    for f in source_dir.rglob("*.kt"):
        if any(ex in f.parts for ex in {"node_modules", ".idea", "target", "build", ".git", "test"}):
            continue

        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except (IOError, UnicodeDecodeError):
            continue

        # Spring Security 설정 탐지
        if 'SecurityWebFilterChain' in content or 'WebSecurityConfigurerAdapter' in content or 'SecurityFilterChain' in content:
            module = detect_module(f, source_dir)

            auth_paths = []
            permit_paths = []

            # pathMatchers(...).authenticated()
            for m in re.finditer(
                r'pathMatchers\s*\(([^)]*)\)\s*\.\s*authenticated\s*\(\s*\)', content
            ):
                paths = re.findall(r'"([^"]*)"', m.group(1))
                auth_paths.extend(paths)

            # pathMatchers(...).permitAll()
            for m in re.finditer(
                r'pathMatchers\s*\(([^)]*)\)\s*\.\s*permitAll\s*\(\s*\)', content
            ):
                paths = re.findall(r'"([^"]*)"', m.group(1))
                permit_paths.extend(paths)

            # .anyExchange().authenticated()
            if re.search(r'anyExchange\s*\(\s*\)\s*\.\s*authenticated', content):
                auth_paths.append("/**")

            # antMatchers(...).authenticated() (MVC style)
            for m in re.finditer(
                r'antMatchers\s*\(([^)]*)\)\s*\.\s*authenticated\s*\(\s*\)', content
            ):
                paths = re.findall(r'"([^"]*)"', m.group(1))
                auth_paths.extend(paths)

            # CSRF 비활성화 확인
            csrf_disabled = bool(re.search(r'csrf\s*(?:\(\s*\))?\s*\.\s*disable', content))

            # CORS 설정 확인
            cors_open = bool(re.search(r'allowedOrigins\s*\(\s*"\*"\s*\)', content))

            module_auth[module] = {
                "auth_paths": auth_paths,
                "permit_paths": permit_paths,
                "csrf_disabled": csrf_disabled,
                "cors_open": cors_open,
                "config_file": str(f.relative_to(source_dir)),
            }

    return module_auth


def is_path_authenticated(api_path: str, module_auth: dict) -> bool:
    """모듈 보안 설정 기반으로 경로가 인증 필요한지 판단"""
    # permitAll 먼저 체크
    for pp in module_auth.get("permit_paths", []):
        pattern = pp.replace("/**", ".*").replace("/*", "[^/]*").replace("*", ".*")
        if re.match(pattern, api_path):
            return False

    # authenticated 체크
    for ap in module_auth.get("auth_paths", []):
        pattern = ap.replace("/**", ".*").replace("/*", "[^/]*").replace("*", ".*")
        if re.match(pattern, api_path):
            return True

    return False


def split_function_params(params_text: str) -> list[str]:
    """함수 파라미터 문자열을 개별 파라미터로 분리 (중첩 괄호 고려)"""
    params = []
    depth = 0
    current = []

    for char in params_text:
        if char in '([':
            depth += 1
            current.append(char)
        elif char in ')]':
            depth -= 1
            current.append(char)
        elif char == ',' and depth == 0:
            params.append(''.join(current).strip())
            current = []
        else:
            current.append(char)

    if current:
        last = ''.join(current).strip()
        if last:
            params.append(last)

    return params


def generate_description(func_name: str, http_method: str, path: str,
                         audit_action: Optional[str], kdoc: str) -> str:
    """핸들러 이름과 컨텍스트에서 설명 자동 생성"""
    if kdoc:
        # KDoc 첫 줄 사용
        first_line = kdoc.strip().split('\n')[0].strip('* ').strip()
        if first_line and first_line != '/**' and first_line != '*/':
            return first_line

    if audit_action:
        return audit_action.replace('_', ' ').title()

    # 함수명에서 설명 생성
    desc = func_name
    # camelCase 분리
    desc = re.sub(r'([a-z])([A-Z])', r'\1 \2', desc).lower()
    return desc


def parse_controller_file(filepath: Path, source_dir: Path,
                          module_auth: dict) -> list[Endpoint]:
    """컨트롤러 파일을 파싱하여 엔드포인트 목록 반환"""
    endpoints = []

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
    except (IOError, UnicodeDecodeError):
        return endpoints

    # @RestController 또는 @Controller 확인
    if not re.search(r'@(?:Rest)?Controller', content):
        return endpoints

    module = detect_module(filepath, source_dir)
    rel_path = str(filepath.relative_to(source_dir))
    mod_auth = module_auth.get(module, {})

    # 클래스명 추출 (class와 이름이 다른 줄에 있을 수 있음)
    class_match = re.search(r'\bclass\s+(\w+)', content)
    class_name = class_match.group(1) if class_match else "Unknown"

    # 클래스 레벨 @RequestMapping 베이스 경로
    base_paths = [""]
    # 클래스 어노테이션 영역에서 @RequestMapping 찾기
    class_keyword_match = re.search(r'\bclass\s', content)
    class_region = content[:class_keyword_match.start()] if class_keyword_match else ""
    rm_content = extract_annotation_value(class_region, 'RequestMapping')
    if rm_content is not None:
        base_paths = extract_paths_from_annotation(rm_content)
        if not base_paths:
            base_paths = [""]

    is_java = filepath.suffix.lower() == ".java"

    # 함수 단위로 파싱
    if not is_java:
        # Kotlin: 어노테이션 블록 + fun 선언
        func_pattern = re.compile(
            r'((?:\s*@\w+(?:\s*\([^)]*(?:\([^)]*\))*[^)]*\))?(?:\s*\n)?)*)'
            r'\s*(?:suspend\s+)?fun\s+(\w+)\s*\(',
            re.MULTILINE
        )
        matches = func_pattern.finditer(content)
    else:
        # Java: 어노테이션 블록 + method 선언
        func_pattern = re.compile(
            r'((?:\s*@\w+(?:\s*\([^)]*\))?\s*)+)'
            r'\s*(?:public|protected|private)?\s*(?:static\s+)?[\w<>\[\], ?]+?\s+(\w+)\s*\(',
            re.MULTILINE
        )
        matches = func_pattern.finditer(content)

    for match in matches:
        anno_block = match.group(1)
        func_name = match.group(2)
        func_start = match.start()
        params_start = match.end()

        # 함수가 시작되는 라인 번호
        line_num = content[:func_start].count('\n') + 1

        # HTTP 메서드 어노테이션 확인
        http_methods = []
        method_paths = []

        for anno_name, http_method in METHOD_ANNOTATIONS.items():
            anno_content = extract_annotation_value(anno_block, anno_name)
            if anno_content is not None:
                http_methods.append(http_method)
                method_paths = extract_paths_from_annotation(anno_content)
            elif re.search(rf'@{anno_name}\b(?!\s*\()', anno_block):
                # 괄호 없는 @GetMapping 등
                http_methods.append(http_method)
                method_paths = [""]

        # @RequestMapping (메서드 지정)
        rm_content = extract_annotation_value(anno_block, 'RequestMapping')
        if rm_content is not None and not http_methods:
            http_methods = extract_method_from_request_mapping(rm_content)
            method_paths = extract_paths_from_annotation(rm_content)
        elif rm_content is not None:
            # 이미 다른 매핑이 있으면 경로만 업데이트
            additional_paths = extract_paths_from_annotation(rm_content)
            if additional_paths and additional_paths != [""]:
                method_paths = additional_paths

        if not http_methods:
            continue  # HTTP 매핑이 없는 함수는 스킵

        # 파라미터 영역 추출 (괄호 매칭)
        depth = 1
        i = params_start
        while i < len(content) and depth > 0:
            if content[i] == '(':
                depth += 1
            elif content[i] == ')':
                depth -= 1
            i += 1
        params_text = content[params_start:i - 1]

        # 반환 타입 추출
        return_type = ""
        after_params = content[i:i + 200]
        rt_match = re.search(r':\s*([^\n{=]+)', after_params)
        if rt_match:
            return_type = rt_match.group(1).strip().rstrip('{').strip()

        # 파라미터 파싱
        param_strings = split_function_params(params_text)
        parameters = []
        for ps in param_strings:
            p = parse_parameter_java(ps) if is_java else parse_parameter(ps)
            if p:
                parameters.append(p)

        # 인증 정보
        preauthorize = extract_preauthorize(anno_block)
        audit_action = extract_audit_action(anno_block)

        # 미들웨어 목록
        middleware = []
        if preauthorize:
            middleware.append(f'@PreAuthorize("{preauthorize}")')
        if audit_action:
            middleware.append(f"@PconaAudit(action='{audit_action}')")
        # @Secured
        secured = extract_annotation_value(anno_block, 'Secured')
        if secured:
            middleware.append(f'@Secured({secured})')

        # KDoc 주석 추출 (함수 바로 위)
        kdoc = ""
        anno_start_line = content[:match.start()].count('\n')
        # 어노테이션 블록 위 줄 검색
        search_start = max(0, anno_start_line - 15)
        pre_lines = lines[search_start:anno_start_line]
        kdoc_lines = []
        in_kdoc = False
        for pl in reversed(pre_lines):
            stripped = pl.strip()
            if stripped.endswith('*/'):
                in_kdoc = True
                kdoc_lines.insert(0, stripped)
            elif in_kdoc:
                kdoc_lines.insert(0, stripped)
                if stripped.startswith('/**') or stripped.startswith('/*'):
                    break
        if kdoc_lines:
            kdoc = '\n'.join(kdoc_lines)

        # 설명 생성
        description = generate_description(
            func_name, http_methods[0], method_paths[0] if method_paths else "",
            audit_action, kdoc
        )

        # 엔드포인트 생성 (base_path × method_path × http_method)
        for http_method in http_methods:
            for base in base_paths:
                for mpath in (method_paths if method_paths else [""]):
                    full_path = (base.rstrip('/') + '/' + mpath.lstrip('/')).rstrip('/')
                    if not full_path:
                        full_path = "/"

                    # 인증 여부 판단
                    auth_required = False
                    auth_detail = ""
                    if preauthorize:
                        auth_required = True
                        auth_detail = preauthorize
                    elif mod_auth:
                        auth_required = is_path_authenticated(full_path, mod_auth)
                        if auth_required:
                            auth_detail = "Security config (path-based)"

                    # @PconaSession 이 있으면 인증 필요
                    if any(p.type == "session" for p in parameters):
                        auth_required = True
                        if not auth_detail:
                            auth_detail = "@PconaSession (authenticated user required)"

                    endpoints.append(Endpoint(
                        method=http_method,
                        api=full_path,
                        auth_required=auth_required,
                        auth_detail=auth_detail,
                        handler=f"{class_name}.{func_name}()",
                        file=rel_path,
                        line=line_num,
                        module=module,
                        description=description,
                        parameters=[asdict(p) for p in parameters],
                        middleware=middleware,
                        return_type=return_type,
                    ))

    return endpoints


# ============================================================
#  디렉토리 스캔
# ============================================================

def prefilter_files_with_search(source_dir: Path,
                                query: str,
                                engine: str = "auto",
                                max_candidates: int = 0) -> list[Path]:
    """code_search.sh 결과에서 파일 경로 후보를 수집"""
    script = Path(__file__).parent / "code_search.sh"
    if not script.exists() or not query:
        return []

    cmd = [str(script), "--repo", str(source_dir), "--query", query, "--engine", engine]
    if max_candidates > 0:
        cmd += ["--max", str(max_candidates)]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError:
        return []

    if result.returncode != 0:
        return []

    files = []
    seen = set()
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        path_str = line.split(":", 1)[0].strip()
        p = Path(path_str)
        if not p.exists() or p.suffix not in {".kt", ".java"}:
            continue
        if source_dir not in p.parents and p != source_dir:
            continue
        if p not in seen:
            seen.add(p)
            files.append(p)
    return files


def scan_directory(source_dir: Path,
                   search_engine: str = "auto",
                   search_query: Optional[str] = None,
                   max_candidates: int = 0,
                   function_context_auto: bool = False,
                   function_context_max: int = 30,
                   function_context_radius: int = 40) -> dict:
    """디렉토리 전체를 스캔하여 API 엔드포인트 추출"""

    # 1. 보안 설정 먼저 탐색
    module_auth = find_security_configs(source_dir)

    # 2. 컨트롤러 파일 탐색
    default_query = r'@RestController|@Controller|@RequestMapping|@GetMapping|@PostMapping|@PutMapping|@DeleteMapping|@PatchMapping'
    pref = prefilter_files_with_search(
        source_dir,
        search_query or default_query,
        search_engine,
        max_candidates,
    )

    if pref:
        controller_files = [f for f in pref if not any(ex in f.parts for ex in {"node_modules", ".idea", "target", "build", ".git", "test"})]
    else:
        controller_files = []
        for f in source_dir.rglob("*.kt"):
            if any(ex in f.parts for ex in {"node_modules", ".idea", "target", "build", ".git", "test"}):
                continue
            controller_files.append(f)
        for f in source_dir.rglob("*.java"):
            if any(ex in f.parts for ex in {"node_modules", ".idea", "target", "build", ".git", "test"}):
                continue
            controller_files.append(f)

    # 3. 각 파일에서 엔드포인트 추출
    all_endpoints = []
    scanned_files = 0
    controller_count = 0

    for f in controller_files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except (IOError, UnicodeDecodeError):
            continue

        scanned_files += 1

        if not re.search(r'@(?:Rest)?Controller', content):
            continue

        controller_count += 1
        endpoints = parse_controller_file(f, source_dir, module_auth)
        all_endpoints.extend(endpoints)

    # 4. 모듈별 통계
    module_stats = {}
    for ep in all_endpoints:
        mod = ep.module
        if mod not in module_stats:
            module_stats[mod] = {"total": 0, "auth_required": 0, "no_auth": 0}
        module_stats[mod]["total"] += 1
        if ep.auth_required:
            module_stats[mod]["auth_required"] += 1
        else:
            module_stats[mod]["no_auth"] += 1

    # 5. HTTP 메서드별 통계
    method_stats = {}
    for ep in all_endpoints:
        m = ep.method
        method_stats[m] = method_stats.get(m, 0) + 1

    result = {
        "source_dir": str(source_dir),
        "total_files_scanned": scanned_files,
        "total_controllers": controller_count,
        "total_endpoints": len(all_endpoints),
        "search_scope": {
            "engine": search_engine,
            "query": search_query or default_query,
            "prefilter_used": bool(pref),
            "prefilter_file_count": len(pref),
        },
        "security_configs": module_auth,
        "module_stats": module_stats,
        "method_stats": method_stats,
        "endpoints": [asdict(ep) for ep in all_endpoints],
    }
    if function_context_auto:
        result["function_context"] = auto_extract_function_context_from_endpoints(
            source_dir=source_dir,
            endpoints=all_endpoints,
            max_hits=function_context_max,
            radius=function_context_radius,
        )
    return result


def auto_extract_function_context_from_endpoints(source_dir: Path,
                                                 endpoints: list[Endpoint],
                                                 max_hits: int,
                                                 radius: int) -> dict:
    """endpoints(file,line) 기반 함수 컨텍스트 추출"""
    script = Path(__file__).parent / "extract_function_context.py"
    if not script.exists():
        return {"enabled": True, "status": "script_missing", "total_contexts": 0, "methods": {}}

    lines = []
    seen = set()
    for ep in endpoints:
        file_path = source_dir / ep.file
        if not file_path.exists():
            continue
        line_no = int(ep.line)
        key = (str(file_path), line_no)
        if key in seen:
            continue
        seen.add(key)
        snippet = f"{ep.method} {ep.api} {ep.handler}"
        lines.append(f"{file_path}:{line_no}:{snippet}")
        if len(lines) >= max_hits:
            break

    if not lines:
        return {"enabled": True, "status": "no_hits", "total_contexts": 0, "methods": {}}

    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as hin:
        hin.write("\n".join(lines))
        hits_path = Path(hin.name)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as hout:
        out_path = Path(hout.name)

    python_bin = os.environ.get("FUNCTION_CONTEXT_PYTHON", sys.executable)
    cmd = [
        python_bin,
        str(script),
        "--hits", str(hits_path),
        "--out", str(out_path),
        "--radius", str(radius),
        "--max", str(max_hits),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return {
            "enabled": True,
            "status": "extract_failed",
            "returncode": proc.returncode,
            "stderr": (proc.stderr or "")[:2000],
            "total_contexts": 0,
            "methods": {},
        }

    try:
        contexts = json.loads(out_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        contexts = []

    methods = {}
    for c in contexts:
        m = c.get("extract_method", "unknown")
        methods[m] = methods.get(m, 0) + 1

    return {
        "enabled": True,
        "status": "ok",
        "total_contexts": len(contexts),
        "methods": methods,
        "contexts": contexts,
    }


# ============================================================
#  메인
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="API 엔드포인트 인벤토리 자동 추출 (Spring MVC/WebFlux 컨트롤러)"
    )
    parser.add_argument(
        "source_dir",
        help="스캔 대상 소스코드 디렉토리",
    )
    parser.add_argument(
        "--output", "-o",
        help="결과 출력 JSON 파일 경로",
        default=None,
    )
    parser.add_argument(
        "--quiet", "-q",
        help="요약만 출력",
        action="store_true",
    )
    parser.add_argument(
        "--search-engine",
        choices=["auto", "rg", "zoekt"],
        default="auto",
        help="코드 검색 엔진 선택 (기본: auto)",
    )
    parser.add_argument(
        "--search-query",
        default=None,
        help="후보 파일 축소용 검색 쿼리 (미지정 시 컨트롤러 기본 쿼리 사용)",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=0,
        help="검색 기반 후보 파일 최대 수 (0=제한 없음)",
    )
    parser.add_argument(
        "--function-context-auto",
        action="store_true",
        help="결과 엔드포인트(file,line) 기준 함수 컨텍스트 자동 추출",
    )
    parser.add_argument(
        "--function-context-max",
        type=int,
        default=30,
        help="함수 컨텍스트 자동 추출 최대 히트 수 (기본: 30)",
    )
    parser.add_argument(
        "--function-context-radius",
        type=int,
        default=40,
        help="fallback 라인 윈도우 반경 (기본: 40)",
    )
    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        print(f"Error: 디렉토리를 찾을 수 없습니다: {source_dir}")
        sys.exit(1)

    print(f"스캔 대상: {source_dir}")
    result = scan_directory(
        source_dir,
        search_engine=args.search_engine,
        search_query=args.search_query,
        max_candidates=args.max_candidates,
        function_context_auto=args.function_context_auto,
        function_context_max=args.function_context_max,
        function_context_radius=args.function_context_radius,
    )

    # 요약 출력
    print(f"\n스캔 완료: {result['total_files_scanned']}개 파일, "
          f"{result['total_controllers']}개 컨트롤러, "
          f"{result['total_endpoints']}개 엔드포인트")

    print(f"\n모듈별:")
    for mod, stats in result["module_stats"].items():
        print(f"  {mod}: {stats['total']}개 "
              f"(인증: {stats['auth_required']}, 비인증: {stats['no_auth']})")

    print(f"\nHTTP 메서드별:")
    for method, count in sorted(result["method_stats"].items()):
        print(f"  {method}: {count}개")

    if not args.quiet:
        # 보안 설정 요약
        if result["security_configs"]:
            print(f"\n보안 설정:")
            for mod, cfg in result["security_configs"].items():
                print(f"  {mod}:")
                print(f"    config: {cfg['config_file']}")
                print(f"    auth paths: {cfg['auth_paths']}")
                print(f"    permit paths: {cfg['permit_paths']}")
                print(f"    CSRF disabled: {cfg['csrf_disabled']}")
                print(f"    CORS open: {cfg['cors_open']}")

        # 엔드포인트 목록
        print(f"\n엔드포인트 목록:")
        for ep in result["endpoints"]:
            auth = "AUTH" if ep["auth_required"] else "OPEN"
            params = ", ".join(
                f"{p['name']}:{p['type']}" for p in ep["parameters"]
                if p["type"] not in ("request", "response", "exchange")
            )
            print(f"  [{ep['method']:6s}] {ep['api']:<40s} [{auth}] "
                  f"{ep['handler']:<40s} params=({params})")

    # 파일 출력
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"\n결과 저장: {output_path}")
    elif not args.quiet:
        print("\n(--output 옵션으로 JSON 파일 저장 가능)")


if __name__ == "__main__":
    main()
