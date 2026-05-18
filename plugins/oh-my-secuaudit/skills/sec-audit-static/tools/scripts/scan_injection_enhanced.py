#!/usr/bin/env python3
"""
인젝션 고도화 진단 스크립트 - endpoint별 양호/취약 판정

scan_api.py 결과를 기반으로 각 API endpoint에 대해
Controller → Service → Repository 호출 흐름을 추적하고,
endpoint별로 SQL Injection 양호/취약/정보를 판정합니다.

추가로 OS Command Injection, SSI Injection 키워드 전역 스캔을 수행합니다.

사용법:
    python scan_injection_enhanced.py <source_dir> --api-inventory <json>
    python scan_injection_enhanced.py testbed/3-pcona/.../pcona-console \
        --api-inventory state/pcona_api_scan.json \
        --modules pcona-console \
        -o state/pcona_task_22_enhanced.json
"""

import json
import re
import sys
import argparse
import subprocess
import tempfile
import os
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime

# scan_injection_patterns.py에서 패턴 가져오기
sys.path.insert(0, str(Path(__file__).parent))
from scan_injection_patterns import (
    OS_CMD_PATTERNS, OS_CMD_SAFE_PATTERNS, OS_CMD_FILTER_CHARS,
    SSI_PATTERNS, scan_file, matches_glob,
)


# ============================================================
#  1. 데이터 구조
# ============================================================

@dataclass
class CallNode:
    """호출 그래프 노드"""
    class_name: str
    file_path: str
    method_name: str
    called_methods: list = field(default_factory=list)  # [(class, method)]


@dataclass
class DbOperation:
    """Repository의 DB 접근 정보"""
    method: str
    access_type: str        # bind, orm, criteria, criteria_tosql, raw_concat, none
    detail: str             # 상세 진단 내역
    line: int = 0
    code_snippet: str = ""
    is_vulnerable: bool = False


@dataclass
class EndpointDiagnosis:
    """Endpoint별 진단 결과"""
    no: str
    platform: str = "WEB"
    check_item: str = "SQL인젝션"
    result: str = "양호"         # 양호 / 취약 / 정보 / N/A
    severity: str = "Risk 2"
    threat: str = "DB정보 유출"

    # API 정보
    http_method: str = ""
    request_mapping: str = ""
    process_file: str = ""
    handler: str = ""
    method_name: str = ""
    parameters: str = ""

    # 흐름 추적
    service_calls: list = field(default_factory=list)
    repository_calls: list = field(default_factory=list)
    db_operations: list = field(default_factory=list)

    # 진단 상세
    filter_type: str = "N/A"
    filter_detail: str = "N/A"
    diagnosis_type: str = ""
    diagnosis_detail: str = ""
    diagnosis_method: str = "자동"
    needs_review: bool = False

    # 코드 증적
    evidence: list = field(default_factory=list)


# ============================================================
#  2. Kotlin/Java 파서 유틸리티
# ============================================================

def read_file_safe(filepath: Path) -> str:
    """파일 안전 읽기"""
    try:
        return filepath.read_text(encoding="utf-8", errors="replace")
    except (IOError, UnicodeDecodeError):
        return ""


def extract_class_name(content: str) -> Optional[str]:
    """클래스명 추출"""
    m = re.search(r'class\s+(\w+)', content)
    return m.group(1) if m else None


def extract_constructor_deps(content: str) -> list:
    """생성자 주입 의존성 추출
    예: class FooController(private val service: FooService, private val bar: BarService)
    Returns: [('service', 'FooService'), ('bar', 'BarService')]
    """
    deps = []

    # Kotlin primary constructor: class Foo(private val x: Type, ...)
    class_match = re.search(r'class\s+\w+\s*\((.*?)\)\s*(?:\{|:)', content, re.DOTALL)
    if class_match:
        params_text = class_match.group(1)
        # private val fieldName: TypeName
        for m in re.finditer(r'(?:private\s+)?(?:val|var)\s+(\w+)\s*:\s*(\w+)', params_text):
            deps.append((m.group(1), m.group(2)))

    # Java field injection: @Autowired private FooService fooService;
    for m in re.finditer(r'@(?:Autowired|Inject)\s+(?:private\s+)?(\w+)\s+(\w+)\s*;', content):
        deps.append((m.group(2), m.group(1)))

    return deps


def extract_method_body(content: str, method_name: str) -> str:
    """메서드 본문 추출 (중괄호 매칭)"""
    # fun methodName( 또는 def methodName(
    pattern = rf'fun\s+{re.escape(method_name)}\s*\('
    match = re.search(pattern, content)
    if not match:
        # Java style: public ReturnType methodName(
        pattern = rf'(?:public|private|protected)?\s+\w+\s+{re.escape(method_name)}\s*\('
        match = re.search(pattern, content)
    if not match:
        return ""

    # 함수 시작부터 본문 추출
    start = match.start()
    # { 를 찾을 때까지
    brace_start = content.find('{', start)
    if brace_start == -1:
        # expression body (= ...) 처리
        eq_pos = content.find('=', start)
        if eq_pos != -1:
            # 다음 fun/class/} 까지
            end = len(content)
            for end_pat in [r'\n\s*fun\s', r'\n\s*class\s', r'\n\}']:
                m = re.search(end_pat, content[eq_pos:])
                if m and eq_pos + m.start() < end:
                    end = eq_pos + m.start()
            return content[start:end]
        return ""

    depth = 0
    i = brace_start
    while i < len(content):
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
            if depth == 0:
                return content[start:i + 1]
        i += 1

    return content[start:]


def extract_method_calls(method_body: str, field_names: list) -> list:
    """메서드 본문에서 특정 필드의 메서드 호출 추출
    예: service.findAll(x, y) → ('service', 'findAll')
    """
    calls = []
    for field_name in field_names:
        pattern = rf'{re.escape(field_name)}\.(\w+)\s*\('
        for m in re.finditer(pattern, method_body):
            method = m.group(1)
            # getter/setter/toString 등 제외
            if method not in ('toString', 'hashCode', 'equals', 'getClass',
                              'get', 'set', 'let', 'also', 'apply', 'run'):
                calls.append((field_name, method))
    return calls


# ============================================================
#  3. Call Graph 구축
# ============================================================

def find_class_file(source_dir: Path, class_name: str,
                    suffixes: list = None) -> Optional[Path]:
    """클래스명으로 파일 찾기"""
    if suffixes is None:
        suffixes = ['.kt', '.java']

    for suffix in suffixes:
        candidates = list(source_dir.rglob(f"{class_name}{suffix}"))
        if candidates:
            return candidates[0]

    # 파일명과 클래스명이 다를 수 있으므로 내용 검색
    for suffix in suffixes:
        for f in source_dir.rglob(f"*{suffix}"):
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                if re.search(rf'class\s+{re.escape(class_name)}\b', content):
                    return f
            except (IOError, UnicodeDecodeError):
                continue
    return None


def build_class_index(source_dir: Path) -> dict:
    """소스 디렉토리의 클래스 인덱스 구축 (클래스명 → 파일 경로)"""
    index = {}
    exclude_dirs = {"node_modules", ".idea", "target", "build", ".git", "dist", "test"}

    for suffix in ('.kt', '.java'):
        for f in source_dir.rglob(f"*{suffix}"):
            if any(ex in f.parts for ex in exclude_dirs):
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                for m in re.finditer(r'(?:class|interface|object)\s+(\w+)', content):
                    index[m.group(1)] = f
            except (IOError, UnicodeDecodeError):
                continue
    return index


def trace_endpoint(endpoint: dict, source_dir: Path,
                   class_index: dict) -> dict:
    """단일 endpoint에 대해 Controller → Service → Repository 추적"""
    result = {
        "service_calls": [],
        "repository_calls": [],
        "db_operations": [],
    }

    # 1. Controller 파일에서 handler 메서드 파싱
    handler = endpoint.get("handler", "")
    file_field = endpoint.get("file", "")

    # handler: "AdController.findAll()"
    handler_match = re.match(r'(\w+)\.(\w+)\s*\(', handler)
    if not handler_match:
        return result

    controller_class = handler_match.group(1)
    handler_method = handler_match.group(2)

    # Controller 파일 찾기
    ctrl_file = None
    if file_field:
        # file 필드에서 경로 추출 (상대경로:라인 형식)
        file_path_str = file_field.split(":")[0]
        candidate = source_dir / file_path_str
        if not candidate.exists():
            # source_dir 상위에서 시도
            candidate = source_dir.parent / file_path_str
        if not candidate.exists():
            # 전체 경로 검색
            for p in source_dir.rglob(Path(file_path_str).name):
                candidate = p
                break
        if candidate.exists():
            ctrl_file = candidate

    if not ctrl_file:
        ctrl_file = class_index.get(controller_class)
    if not ctrl_file:
        return result

    ctrl_content = read_file_safe(ctrl_file)
    if not ctrl_content:
        return result

    # 2. Controller의 의존성 추출
    ctrl_deps = extract_constructor_deps(ctrl_content)
    service_fields = [(name, cls) for name, cls in ctrl_deps
                      if cls.endswith('Service') or cls.endswith('UseCase')]

    # 3. Handler 메서드 본문에서 service 호출 추출
    method_body = extract_method_body(ctrl_content, handler_method)
    if not method_body:
        return result

    svc_field_names = [name for name, _ in service_fields]
    svc_calls = extract_method_calls(method_body, svc_field_names)

    for field_name, svc_method in svc_calls:
        # field → class 매핑
        svc_class = None
        for fname, cls in service_fields:
            if fname == field_name:
                svc_class = cls
                break
        if not svc_class:
            continue

        result["service_calls"].append(f"{svc_class}.{svc_method}()")

        # 4. Service 파일 찾기 → Repository 호출 추적
        svc_file = class_index.get(svc_class)
        if not svc_file:
            continue

        svc_content = read_file_safe(svc_file)
        if not svc_content:
            continue

        svc_deps = extract_constructor_deps(svc_content)
        repo_fields = [(name, cls) for name, cls in svc_deps
                       if any(cls.endswith(s) for s in
                              ('Repository', 'Mapper', 'Dao', 'DAO'))]

        svc_method_body = extract_method_body(svc_content, svc_method)
        if not svc_method_body:
            continue

        repo_field_names = [name for name, _ in repo_fields]
        repo_calls = extract_method_calls(svc_method_body, repo_field_names)

        for repo_field, repo_method in repo_calls:
            # field → class 매핑
            repo_class = None
            for fname, cls in repo_fields:
                if fname == repo_field:
                    repo_class = cls
                    break
            if not repo_class:
                continue

            result["repository_calls"].append(f"{repo_class}.{repo_method}()")

            # 5. Repository 메서드의 DB 접근 방식 분석
            repo_file = class_index.get(repo_class)
            if not repo_file:
                continue

            repo_content = read_file_safe(repo_file)
            if not repo_content:
                continue

            db_ops = analyze_repository_method(repo_content, repo_method,
                                                repo_file)
            result["db_operations"].extend(db_ops)

    return result


# ============================================================
#  4. Repository DB 접근 분석
# ============================================================

def analyze_repository_method(content: str, method_name: str,
                               file_path: Path = None) -> list:
    """Repository 메서드의 DB 접근 패턴을 분석하여 진단 유형 결정

    우선순위:
      1. 메서드 본문에서 직접 사용하는 DB 접근 패턴 확인
      2. 양호/취약 패턴이 공존 시 메서드의 주된 작업 기준으로 판정
      3. ORM(.using(entity)) > bind > criteria > raw_concat 순으로 판정
    """
    ops = []
    method_body = extract_method_body(content, method_name)
    if not method_body:
        return ops

    lines = method_body.splitlines()

    # 메서드 시작 라인 번호 계산
    all_lines = content.splitlines()
    method_start_line = 0
    for i, line in enumerate(all_lines):
        if re.search(rf'fun\s+{re.escape(method_name)}\s*\(', line):
            method_start_line = i + 1
            break

    def find_line(match_obj):
        idx = method_body[:match_obj.start()].count('\n')
        code = lines[idx].strip() if idx < len(lines) else ""
        return method_start_line + idx, code

    # --- 1단계: 모든 패턴 수집 ---

    found_orm = False
    found_bind = False
    found_criteria_safe = False
    found_criteria_tosql = False
    found_raw_concat = False
    found_execute = bool(re.search(r'\.execute\s*\(', method_body))

    # ORM: .using(entity) - insert/update/delete
    if re.search(r'\.(?:insert|update|delete)\s*\(\s*\)\s*\.'
                 r'(?:into|table|from)',
                 method_body, re.DOTALL):
        found_orm = True
    if re.search(r'\.using\s*\(', method_body):
        found_orm = True

    # .bind() 파라미터 바인딩
    if re.search(r'\.bind\s*\(\s*["\']', method_body):
        found_bind = True

    # Criteria DSL (.matching)
    if re.search(r'\.matching\s*\(', method_body):
        if re.search(r'Utils\.toSql', method_body):
            found_criteria_tosql = True
        else:
            found_criteria_safe = True

    # Utils.toSql() (execute 컨텍스트)
    if re.search(r'Utils\.toSql\s*\(', method_body):
        found_criteria_tosql = True

    # Raw SQL concat
    concat_patterns = [
        (r'(?:\.execute|\.sql)\s*\([^)]*\+', "Raw SQL 문자열 결합 (+)"),
        (r'buildString\s*\{', "buildString으로 SQL 동적 생성"),
        (r'String\.format\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)',
         "String.format()으로 SQL 생성"),
        (r'\.format\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)',
         ".format()으로 SQL 생성"),
    ]
    raw_concat_desc = ""
    for pat, desc in concat_patterns:
        if re.search(pat, method_body, re.IGNORECASE | re.DOTALL):
            found_raw_concat = True
            raw_concat_desc = desc
            break

    # buildString 은 SQL 컨텍스트인지 확인
    if found_raw_concat and "buildString" in raw_concat_desc:
        # buildString 주변에 SQL 키워드가 있는지 확인
        if not re.search(r'(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|_SQL|\.execute|\.sql)',
                         method_body, re.IGNORECASE):
            found_raw_concat = False

    # --- 2단계: 우선순위 기반 판정 ---

    # 메서드명에서 작업 유형 추론
    is_create = any(kw in method_name.lower()
                    for kw in ('create', 'insert', 'register', 'save', 'add'))
    is_update = any(kw in method_name.lower()
                    for kw in ('update', 'modify', 'set', 'reset', 'change'))
    is_delete = any(kw in method_name.lower()
                    for kw in ('delete', 'remove'))
    is_write_op = is_create or is_update or is_delete

    # 쓰기 작업이면서 ORM 사용 → ORM이 주된 패턴
    if is_write_op and found_orm:
        ops.append(DbOperation(
            method=method_name,
            access_type="orm",
            detail="유형2: ORM 방식으로 객체 바인딩하여 DB 처리",
            is_vulnerable=False,
        ))
        return ops

    # 쓰기 작업이면서 bind 사용 → bind가 주된 패턴
    if is_write_op and found_bind:
        bind_m = re.search(r'\.bind\s*\(\s*["\']', method_body)
        line_no, code = find_line(bind_m)
        ops.append(DbOperation(
            method=method_name,
            access_type="bind",
            detail="유형1: 파라미터에 대해 : 바인딩",
            line=line_no,
            code_snippet=code,
            is_vulnerable=False,
        ))
        return ops

    # Utils.toSql() 취약 패턴 (쓰기 작업이 아닌 경우)
    if found_criteria_tosql:
        tosql_m = re.search(r'Utils\.toSql\s*\(', method_body)
        line_no, code = find_line(tosql_m)
        ops.append(DbOperation(
            method=method_name,
            access_type="criteria_tosql",
            detail="취약: Utils.toSql()이 CriteriaDefinition.toString()을 SQL에 직접 삽입",
            line=line_no,
            code_snippet=code,
            is_vulnerable=True,
        ))
        return ops

    # Raw SQL concat (쓰기 작업이 아닌 경우)
    if found_raw_concat and not is_write_op:
        for pat, desc in concat_patterns:
            m = re.search(pat, method_body, re.IGNORECASE | re.DOTALL)
            if m:
                line_no, code = find_line(m)
                ops.append(DbOperation(
                    method=method_name,
                    access_type="raw_concat",
                    detail=f"취약: {desc}",
                    line=line_no,
                    code_snippet=code,
                    is_vulnerable=True,
                ))
                return ops

    # Raw SQL concat + 쓰기 작업 → bind/orm이 없는 경우만 취약
    if found_raw_concat and is_write_op and not found_bind and not found_orm:
        for pat, desc in concat_patterns:
            m = re.search(pat, method_body, re.IGNORECASE | re.DOTALL)
            if m:
                line_no, code = find_line(m)
                ops.append(DbOperation(
                    method=method_name,
                    access_type="raw_concat",
                    detail=f"취약: {desc}",
                    line=line_no,
                    code_snippet=code,
                    is_vulnerable=True,
                ))
                return ops

    # --- 양호 패턴 ---

    if found_bind:
        bind_m = re.search(r'\.bind\s*\(\s*["\']', method_body)
        line_no, code = find_line(bind_m)
        ops.append(DbOperation(
            method=method_name,
            access_type="bind",
            detail="유형1: 파라미터에 대해 : 바인딩",
            line=line_no,
            code_snippet=code,
            is_vulnerable=False,
        ))
        return ops

    if found_orm:
        ops.append(DbOperation(
            method=method_name,
            access_type="orm",
            detail="유형2: ORM 방식으로 객체 바인딩하여 DB 처리",
            is_vulnerable=False,
        ))
        return ops

    if found_criteria_safe:
        ops.append(DbOperation(
            method=method_name,
            access_type="criteria",
            detail="유형3: Criteria 기반 쿼리 방식으로 DB 처리",
            is_vulnerable=False,
        ))
        return ops

    # R2dbcEntityTemplate
    if re.search(r'R2dbcEntityTemplate|\.select\s*\(\s*\w+::class', method_body):
        ops.append(DbOperation(
            method=method_name,
            access_type="orm",
            detail="유형2: R2dbcEntityTemplate 사용",
            is_vulnerable=False,
        ))
        return ops

    # .execute + :param
    if found_execute:
        if re.search(r':\w+', method_body) and \
           not re.search(r'\.toString\s*\(\s*\)', method_body):
            ops.append(DbOperation(
                method=method_name,
                access_type="bind",
                detail="유형1: SQL에 :param 바인딩 사용",
                is_vulnerable=False,
            ))
            return ops

    # DB 접근 없음
    if not re.search(r'\.(?:execute|sql|select|insert|update|delete|query)\s*\(',
                     method_body, re.IGNORECASE):
        ops.append(DbOperation(
            method=method_name,
            access_type="none",
            detail="DB 접근 없음",
            is_vulnerable=False,
        ))
        return ops

    # 판정 불가
    ops.append(DbOperation(
        method=method_name,
        access_type="unknown",
        detail="자동 판정 불가 - 수동 검토 필요",
        is_vulnerable=False,
    ))
    return ops


# ============================================================
#  5. Endpoint별 판정
# ============================================================

def has_db_input_params(params: list) -> bool:
    """endpoint 파라미터 중 DB 쿼리에 영향을 줄 수 있는 사용자 입력이 있는지"""
    if not params:
        return False
    # 사용자가 직접 제어 가능한 파라미터 유형
    skip_types = {"User", "ServerWebExchange", "ServerHttpRequest",
                  "ServerHttpResponse", "WebSession", "Authentication",
                  "Principal", "Model", "BindingResult", "Errors"}
    for p in params:
        p_type = p.get("type", "")
        data_type = p.get("data_type", "")
        if p_type in ("query", "path", "body") and data_type not in skip_types:
            return True
        if p_type == "pageable":
            return True  # Pageable의 sort 파라미터 가능
    return False


def has_search_like_params(params: list) -> bool:
    """검색/필터 관련 파라미터가 있는지 (toSql 영향 가능)"""
    search_names = {"search", "keyword", "query", "q", "field", "value",
                    "filter", "term", "name", "title", "text"}
    for p in params:
        p_name = p.get("name", "").lower()
        if p_name in search_names:
            return True
        if p.get("type") == "query" and p.get("data_type", "") == "String":
            return True
    return False


def is_non_db_endpoint(endpoint: dict) -> bool:
    """DB 접근이 필요 없는 엔드포인트인지 판별"""
    mapping = endpoint.get("api", "")
    handler = endpoint.get("handler", "")

    non_db_patterns = [
        r'/health', r'/actuator', r'/diagnosis',
        r'/callback', r'/login', r'/logout',
        r'/static/', r'\.jsp$', r'/ws/',
    ]
    for pat in non_db_patterns:
        if re.search(pat, mapping, re.IGNORECASE):
            return True
    return False


def judge_endpoint(trace_result: dict, endpoint: dict) -> dict:
    """endpoint에 대한 최종 양호/취약/정보 판정"""
    db_ops = trace_result.get("db_operations", [])
    params = endpoint.get("parameters", [])

    has_user_params = has_db_input_params(params)
    has_search_params = has_search_like_params(params)

    # 비DB 엔드포인트 (healthcheck, login 등) → 양호
    if is_non_db_endpoint(endpoint):
        if not trace_result.get("service_calls"):
            return {
                "result": "양호",
                "diagnosis_type": "비DB 엔드포인트",
                "diagnosis_detail": "DB 접근이 필요 없는 엔드포인트 (healthcheck/login/callback 등)",
                "filter_type": "N/A",
                "filter_detail": "N/A",
                "needs_review": False,
            }

    if not db_ops:
        # Repository 추적 실패
        if not trace_result.get("service_calls"):
            # Service 호출도 없으면 비DB 가능성 높음
            if not has_user_params:
                return {
                    "result": "양호",
                    "diagnosis_type": "Service 미호출",
                    "diagnosis_detail": "Controller에서 Service/Repository 호출 없음 - DB 접근 없는 엔드포인트",
                    "filter_type": "N/A",
                    "filter_detail": "N/A",
                    "needs_review": False,
                }
            return {
                "result": "정보",
                "diagnosis_type": "추적 불가",
                "diagnosis_detail": "Controller→Service→Repository 자동 추적 실패 - 수동 검토 필요",
                "filter_type": "N/A",
                "filter_detail": "N/A",
                "needs_review": True,
            }
        return {
            "result": "정보",
            "diagnosis_type": "DB 접근 미확인",
            "diagnosis_detail": "Service 호출 확인되나 Repository DB 접근 추적 불가",
            "filter_type": "N/A",
            "filter_detail": "N/A",
            "needs_review": True,
        }

    # 취약 패턴 존재 여부
    vulnerable_ops = [op for op in db_ops if op.is_vulnerable]
    safe_ops = [op for op in db_ops if not op.is_vulnerable and
                op.access_type != "none"]

    if vulnerable_ops:
        op = vulnerable_ops[0]

        # 취약 판정 세분화:
        # - Utils.toSql() + 검색 파라미터 → 취약
        # - Utils.toSql() + Pageable만 → 정보 (sort 파라미터로 제한적)
        # - Utils.toSql() + 파라미터 없음 → 정보
        # - Raw concat + 사용자 입력 → 취약
        # - Raw concat + 내부 파라미터만 → 정보
        if op.access_type == "criteria_tosql":
            if has_search_params:
                result_str = "취약"
                detail = op.detail
            elif has_user_params:
                result_str = "정보"
                detail = op.detail + " (사용자 입력값이 Criteria에 간접 전달될 수 있음)"
            else:
                result_str = "정보"
                detail = op.detail + " (사용자 입력 파라미터 없어 직접 입력 불가)"
        elif op.access_type == "raw_concat":
            if has_search_params:
                result_str = "취약"
                detail = op.detail
            elif has_user_params:
                result_str = "정보"
                detail = op.detail + " (사용자 파라미터가 SQL 결합에 도달하는지 수동 확인 필요)"
            else:
                result_str = "정보"
                detail = op.detail + " (사용자 입력 파라미터 없음)"
        else:
            result_str = "취약" if has_user_params else "정보"
            detail = op.detail

        filter_type = "N/A"
        filter_detail = "N/A"
        if op.access_type == "criteria_tosql":
            filter_type = "r2dbc"
            filter_detail = "toSql()"

        return {
            "result": result_str,
            "diagnosis_type": op.detail.split(":")[0].strip() if ":" in op.detail else op.access_type,
            "diagnosis_detail": detail,
            "filter_type": filter_type,
            "filter_detail": filter_detail,
            "needs_review": result_str == "정보" and has_user_params,
            "evidence": [{
                "file": str(op.code_snippet),
                "line": op.line,
                "detail": op.detail,
            }] if op.code_snippet else [],
        }

    if safe_ops:
        op = safe_ops[0]
        filter_type = "r2dbc"
        filter_detail = ":"
        if op.access_type == "orm":
            filter_detail = "orm"
        elif op.access_type == "criteria":
            filter_detail = "criteria"
        elif op.access_type == "bind":
            filter_detail = ":"

        return {
            "result": "양호",
            "diagnosis_type": op.detail,
            "diagnosis_detail": op.detail,
            "filter_type": filter_type,
            "filter_detail": filter_detail,
            "needs_review": False,
        }

    # DB 접근 없음
    no_db_ops = [op for op in db_ops if op.access_type == "none"]
    if no_db_ops:
        if not has_user_params:
            return {
                "result": "양호",
                "diagnosis_type": "유형4: DB처리에 사용되는 파라미터없음",
                "diagnosis_detail": "유형4: DB처리에 사용되는 파라미터없음",
                "filter_type": "r2dbc",
                "filter_detail": "N/A",
                "needs_review": False,
            }
        return {
            "result": "양호",
            "diagnosis_type": "DB 접근 없음",
            "diagnosis_detail": "이 endpoint의 Repository 메서드에서 직접 DB 접근 없음",
            "filter_type": "N/A",
            "filter_detail": "N/A",
            "needs_review": False,
        }

    # unknown
    return {
        "result": "정보",
        "diagnosis_type": "자동 판정 불가",
        "diagnosis_detail": "자동 판정 불가 - 수동 검토 필요",
        "filter_type": "N/A",
        "filter_detail": "N/A",
        "needs_review": True,
    }


# ============================================================
#  6. OS Command / SSI 전역 스캔
# ============================================================

def scan_global_patterns(source_dir: Path, context_lines: int = 3) -> dict:
    """OS Command Injection / SSI Injection 전역 스캔"""
    extensions = {".kt", ".java", ".xml", ".js", ".ts", ".jsx", ".tsx",
                  ".php", ".py", ".cs", ".vb", ".groovy",
                  ".html", ".shtml", ".stm", ".shtm", ".jsp", ".vue",
                  ".ejs", ".njk", ".hbs"}

    exclude_dirs = {"node_modules", ".idea", "target", "build", ".git", "dist"}

    all_files = []
    for ext in extensions:
        for f in source_dir.rglob(f"*{ext}"):
            if not any(ex in f.parts for ex in exclude_dirs):
                all_files.append(f)

    # OS Command Injection
    cmd_findings = []
    for f in all_files:
        cmd_findings.extend(scan_file(f, OS_CMD_PATTERNS,
                                       OS_CMD_SAFE_PATTERNS, context_lines))

    # SSI Injection
    ssi_findings = []
    for f in all_files:
        ssi_findings.extend(scan_file(f, SSI_PATTERNS, [], context_lines))

    # 상대 경로 변환
    for finding in cmd_findings + ssi_findings:
        try:
            finding.file = str(Path(finding.file).relative_to(source_dir))
        except ValueError:
            pass

    return {
        "os_command_injection": {
            "total": len(cmd_findings),
            "findings": [asdict(f) for f in cmd_findings],
        },
        "ssi_injection": {
            "total": len(ssi_findings),
            "findings": [asdict(f) for f in ssi_findings],
        },
    }


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

    exts = {".kt", ".java", ".xml", ".js", ".ts", ".jsx", ".tsx",
            ".php", ".py", ".cs", ".vb", ".groovy",
            ".html", ".shtml", ".stm", ".shtm", ".jsp", ".vue",
            ".ejs", ".njk", ".hbs"}
    files = []
    seen = set()
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        path_str = line.split(":", 1)[0].strip()
        p = Path(path_str)
        if not p.exists() or p.suffix not in exts:
            continue
        if source_dir not in p.parents and p != source_dir:
            continue
        if p not in seen:
            seen.add(p)
            files.append(p)
    return files


def scan_global_patterns_scoped(source_dir: Path, context_lines: int = 3,
                                search_engine: str = "auto",
                                search_query: Optional[str] = None,
                                max_candidates: int = 0) -> dict:
    """전역 스캔의 범위를 검색 결과로 축소한 버전"""
    if not search_query:
        result = scan_global_patterns(source_dir, context_lines)
        result["search_scope"] = {
            "engine": search_engine,
            "query": "",
            "prefilter_used": False,
            "prefilter_file_count": 0,
        }
        return result

    pref = prefilter_files_with_search(source_dir, search_query, search_engine, max_candidates)
    if not pref:
        result = scan_global_patterns(source_dir, context_lines)
        result["search_scope"] = {
            "engine": search_engine,
            "query": search_query,
            "prefilter_used": False,
            "prefilter_file_count": 0,
        }
        return result

    cmd_findings = []
    ssi_findings = []
    for f in pref:
        cmd_findings.extend(scan_file(f, OS_CMD_PATTERNS, OS_CMD_SAFE_PATTERNS, context_lines))
        ssi_findings.extend(scan_file(f, SSI_PATTERNS, [], context_lines))

    for finding in cmd_findings + ssi_findings:
        try:
            finding.file = str(Path(finding.file).relative_to(source_dir))
        except ValueError:
            pass

    return {
        "os_command_injection": {
            "total": len(cmd_findings),
            "findings": [asdict(f) for f in cmd_findings],
        },
        "ssi_injection": {
            "total": len(ssi_findings),
            "findings": [asdict(f) for f in ssi_findings],
        },
        "search_scope": {
            "engine": search_engine,
            "query": search_query,
            "prefilter_used": True,
            "prefilter_file_count": len(pref),
        },
    }


# ============================================================
#  7. 메인 로직
# ============================================================

def load_api_inventory(inventory_path: Path, modules: list = None) -> list:
    """API 인벤토리 로드 (scan_api.py 출력 또는 task_21_result.json)"""
    with open(inventory_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # scan_api.py 출력 형식
    if "endpoints" in data:
        endpoints = data["endpoints"]
    # task_21_result.json 형식
    elif "findings" in data:
        endpoints = data["findings"]
    else:
        print(f"Error: 지원하지 않는 인벤토리 형식입니다: {inventory_path}")
        sys.exit(1)

    # 모듈 필터
    if modules:
        endpoints = [ep for ep in endpoints
                     if ep.get("module", "") in modules]

    return endpoints


def format_params(params: list) -> str:
    """파라미터 목록을 문자열로 포맷"""
    if not params:
        return "N/A"
    parts = []
    for p in params:
        name = p.get("name", "?")
        data_type = p.get("data_type", p.get("type", ""))
        if data_type:
            parts.append(f"{name}: {data_type}")
        else:
            parts.append(name)
    return ", ".join(parts)


def run_diagnosis(source_dir: Path, inventory_path: Path,
                  modules: list = None,
                  context_lines: int = 3,
                  search_engine: str = "auto",
                  search_query: Optional[str] = None,
                  max_candidates: int = 0,
                  function_context_auto: bool = False,
                  function_context_max: int = 30,
                  function_context_radius: int = 40) -> dict:
    """전체 진단 실행"""

    # 1. API 인벤토리 로드
    endpoints = load_api_inventory(inventory_path, modules)
    print(f"API 인벤토리 로드: {len(endpoints)}개 endpoint")

    # 2. 클래스 인덱스 구축
    print("클래스 인덱스 구축 중...")
    class_index = build_class_index(source_dir)
    print(f"  → {len(class_index)}개 클래스 인덱싱 완료")

    # 3. Endpoint별 진단
    print("Endpoint별 진단 수행 중...")
    diagnoses = []
    counter = 0

    for ep in endpoints:
        counter += 1
        no = f"1-{counter}"

        # 호출 흐름 추적
        trace = trace_endpoint(ep, source_dir, class_index)

        # 판정
        judgment = judge_endpoint(trace, ep)

        diag = EndpointDiagnosis(
            no=no,
            http_method=ep.get("method", ""),
            request_mapping=ep.get("api", ""),
            process_file=ep.get("file", ""),
            handler=ep.get("handler", ""),
            method_name=ep.get("handler", "").split(".")[-1].rstrip("()") if ep.get("handler") else "",
            parameters=format_params(ep.get("parameters", [])),
            service_calls=trace.get("service_calls", []),
            repository_calls=trace.get("repository_calls", []),
            db_operations=[asdict(op) for op in trace.get("db_operations", [])],
            result=judgment["result"],
            filter_type=judgment.get("filter_type", "N/A"),
            filter_detail=judgment.get("filter_detail", "N/A"),
            diagnosis_type=judgment.get("diagnosis_type", ""),
            diagnosis_detail=judgment.get("diagnosis_detail", ""),
            needs_review=judgment.get("needs_review", False),
            evidence=judgment.get("evidence", []),
        )
        diagnoses.append(diag)

    # 통계
    sqli_stats = {"양호": 0, "취약": 0, "정보": 0, "N/A": 0}
    for d in diagnoses:
        sqli_stats[d.result] = sqli_stats.get(d.result, 0) + 1

    print(f"\nSQLi 진단 완료: {len(diagnoses)}개 endpoint")
    for k, v in sqli_stats.items():
        if v > 0:
            print(f"  {k}: {v}건")

    review_count = sum(1 for d in diagnoses if d.needs_review)
    if review_count > 0:
        print(f"  수동 검토 필요: {review_count}건")

    # 4. OS Command / SSI 전역 스캔
    print("\nOS Command / SSI Injection 전역 스캔 중...")
    global_findings = scan_global_patterns_scoped(
        source_dir,
        context_lines,
        search_engine=search_engine,
        search_query=search_query,
        max_candidates=max_candidates,
    )
    print(f"  OS Command Injection: {global_findings['os_command_injection']['total']}건")
    print(f"  SSI Injection: {global_findings['ssi_injection']['total']}건")

    result = {
        "task_id": "2-2",
        "status": "completed",
        "scan_metadata": {
            "source_dir": str(source_dir),
            "api_inventory": str(inventory_path),
            "modules_filtered": modules or [],
            "total_endpoints": len(endpoints),
            "total_classes_indexed": len(class_index),
            "scanned_at": datetime.now().isoformat(),
            "script_version": "2.0.0",
            "search_scope": global_findings.get("search_scope", {}),
        },
        "endpoint_diagnoses": [asdict(d) for d in diagnoses],
        "global_findings": global_findings,
        "summary": {
            "total_endpoints": len(diagnoses),
            "sqli": sqli_stats,
            "os_command": {
                "total": global_findings["os_command_injection"]["total"]
            },
            "ssi": {
                "total": global_findings["ssi_injection"]["total"]
            },
            "needs_review": review_count,
        },
        "executed_at": datetime.now().isoformat(),
    }

    if function_context_auto:
        # global findings 중심으로 함수 컨텍스트 추출
        merged = []
        for f in global_findings.get("os_command_injection", {}).get("findings", []):
            merged.append({"file": f.get("file"), "line": f.get("line"), "code_snippet": f.get("code_snippet", "")})
        for f in global_findings.get("ssi_injection", {}).get("findings", []):
            merged.append({"file": f.get("file"), "line": f.get("line"), "code_snippet": f.get("code_snippet", "")})

        result["function_context"] = auto_extract_function_context_from_dicts(
            source_dir,
            merged,
            max_hits=function_context_max,
            radius=function_context_radius,
        )

    return result


def auto_extract_function_context_from_dicts(source_dir: Path,
                                             findings: list[dict],
                                             max_hits: int,
                                             radius: int) -> dict:
    """dict findings(file,line) 기반 함수 컨텍스트 추출"""
    script = Path(__file__).parent / "extract_function_context.py"
    if not script.exists():
        return {"enabled": True, "status": "script_missing", "total_contexts": 0, "methods": {}}

    lines = []
    seen = set()
    for f in findings:
        rel_file = f.get("file")
        line_no = f.get("line")
        if not rel_file or not isinstance(line_no, int) or line_no <= 0:
            continue
        file_path = source_dir / rel_file
        if not file_path.exists():
            continue
        key = (str(file_path), line_no)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"{file_path}:{line_no}:{f.get('code_snippet', '')}")
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


def main():
    parser = argparse.ArgumentParser(
        description="인젝션 고도화 진단 - endpoint별 양호/취약 판정"
    )
    parser.add_argument(
        "source_dir",
        help="스캔 대상 소스코드 디렉토리",
    )
    parser.add_argument(
        "--api-inventory", "-a",
        required=True,
        help="API 인벤토리 JSON 파일 (scan_api.py 출력 또는 task_21_result.json)",
    )
    parser.add_argument(
        "--modules", "-m",
        nargs="*",
        help="진단 대상 모듈 필터 (예: pcona-console)",
    )
    parser.add_argument(
        "--output", "-o",
        help="결과 출력 JSON 파일 경로",
        default=None,
    )
    parser.add_argument(
        "--context-lines", "-c",
        help="매칭 줄 전후 컨텍스트 줄 수 (기본: 3)",
        type=int,
        default=3,
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
        help="전역 패턴 스캔 후보 축소용 검색 쿼리",
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
        help="탐지된 file:line에 대해 함수 컨텍스트 후처리 자동 실행",
    )
    parser.add_argument(
        "--function-context-max",
        type=int,
        default=30,
        help="함수 컨텍스트 추출 최대 hit 수",
    )
    parser.add_argument(
        "--function-context-radius",
        type=int,
        default=40,
        help="함수 추출 최종 fallback 윈도우 반경",
    )
    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        print(f"Error: 디렉토리를 찾을 수 없습니다: {source_dir}")
        sys.exit(1)

    inventory_path = Path(args.api_inventory)
    if not inventory_path.exists():
        print(f"Error: 인벤토리 파일을 찾을 수 없습니다: {inventory_path}")
        sys.exit(1)

    result = run_diagnosis(
        source_dir,
        inventory_path,
        args.modules,
        args.context_lines,
        search_engine=args.search_engine,
        search_query=args.search_query,
        max_candidates=args.max_candidates,
        function_context_auto=args.function_context_auto,
        function_context_max=args.function_context_max,
        function_context_radius=args.function_context_radius,
    )

    # 파일 출력
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"\n결과 저장: {output_path}")
    else:
        # stdout 요약
        print("\n(--output 옵션으로 JSON 파일 저장 가능)")


if __name__ == "__main__":
    main()
