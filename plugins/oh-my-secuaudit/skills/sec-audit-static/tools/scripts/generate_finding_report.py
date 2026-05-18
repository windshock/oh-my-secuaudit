#!/usr/bin/env python3
"""
취약점 진단 결과 상세 보고서 생성 스크립트

각 Task 결과를 개발자 친화적인 Markdown 보고서로 변환합니다.
취약점별로 영향받는 코드 증적(evidence)을 포함하여 조치가 용이하도록 합니다.

사용법:
    python generate_finding_report.py <source_dir> <finding_results...> --output <report.md>
    python generate_finding_report.py testbed/3-pcona/pcona-env-dev@afd19907e2c/ \
        state/pcona_task_22_result.json state/pcona_task_23_result.json \
        --service "PCoNA 관리콘솔" --output state/pcona_진단보고서.md

출력 형식:
    - 서비스 개요 및 진단 범위
    - 진단 결과 요약 표
    - 카테고리별 취약점 상세 (코드 증적 포함)
"""

import json
import re
import sys
import os
import argparse
from pathlib import Path
from datetime import date
from dataclasses import dataclass, field
from typing import Optional


# =============================================================================
#  상수 정의
# =============================================================================

# Task ID → 카테고리 매핑
CATEGORY_INFO = {
    "injection": {
        "name": "인젝션",
        "number": "1",
        "threat": "DB/서버 침투, 정보 탈취",
        "items": {
            "sql": "SQL 인젝션",
            "os_command": "OS Command 인젝션",
            "ssi": "SSI/SSTI 인젝션",
            "ssti": "SSI/SSTI 인젝션",
            "nosql": "NoSQL 인젝션",
        }
    },
    "xss": {
        "name": "XSS",
        "number": "2",
        "threat": "세션 탈취, 피싱, 악성코드 배포",
        "items": {
            "persistent": "Persistent XSS",
            "reflected": "Reflected XSS",
            "dom": "DOM-based XSS",
            "redirect": "Open Redirect",
        }
    },
    "file_handling": {
        "name": "파일 처리",
        "number": "3",
        "threat": "웹쉘 업로드, 서버 파일 노출",
        "items": {
            "upload": "파일 업로드",
            "download": "파일 다운로드",
            "lfi": "로컬 파일 인클루전",
            "path_traversal": "경로 탐색",
        }
    },
    "data_protection": {
        "name": "데이터 보호",
        "number": "4",
        "threat": "정보 노출, 계정 탈취",
        "items": {
            "info_leak": "정보 누출",
            "hardcoded": "하드코딩된 비밀정보",
            "cors": "CORS 설정 미흡",
            "jwt": "JWT 취약점",
            "csrf": "CSRF 보호 미흡",
        }
    },
    "auth_payment": {
        "name": "인증/결제",
        "number": "6",
        "threat": "무단 상태 변경, 권한 오남용",
        "items": {
            "authz": "인증·권한",
            "integrity": "요청 무결성",
            "replay": "재전송 방지",
            "state_change": "상태 변경 보호",
        }
    },
}

# severity → 위험도
RISK_MAP = {
    "critical": ("취약", 5),
    "high": ("취약", 5),
    "medium": ("정보", 4),
    "low": ("양호", 3),
    "info": ("정보", 4),
}

ANCHOR_STYLE = "confluence"
ANCHOR_PREFIX = ""
TRANSLATE_FINDINGS_KO = os.environ.get("TRANSLATE_FINDINGS_KO", "").lower() in {"1", "true", "yes"}
GLOSSARY_PATH = os.environ.get(
    "TRANSLATION_GLOSSARY_PATH",
    str(Path(__file__).resolve().parent.parent / "translation_glossary.json")
)


def _load_glossary() -> dict[str, str]:
    if not TRANSLATE_FINDINGS_KO:
        return {}
    try:
        path = Path(GLOSSARY_PATH)
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _apply_glossary(text: str, glossary: dict[str, str]) -> str:
    if not text or not glossary:
        return text
    # Replace longer phrases first to avoid partial overrides
    for key in sorted(glossary.keys(), key=len, reverse=True):
        val = glossary[key]
        if key in text:
            text = text.replace(key, val)
    return text


def _anchor(name: str) -> str:
    if ANCHOR_STYLE == "html":
        return ""
    if ANCHOR_STYLE == "md2cf":
        return ""
    return f"[[ANCHOR:{name}]]"


def _html_table(headers: list[str], rows: list[list[str]]) -> str:
    def td(val: str) -> str:
        return f"<td>{val}</td>"
    def th(val: str) -> str:
        return f"<th>{val}</th>"
    lines = ["<table><tbody>"]
    lines.append("<tr>" + "".join(th(h) for h in headers) + "</tr>")
    for row in rows:
        lines.append("<tr>" + "".join(td(c) for c in row) + "</tr>")
    lines.append("</tbody></table>")
    return "\n".join(lines)


def _anchor_link(name: str, text: str) -> str:
    if ANCHOR_STYLE == "md2cf" and ANCHOR_PREFIX:
        return f"[{text}](#{ANCHOR_PREFIX}-{name})"
    return f"[{text}](#{name})"


def _normalize_anchor_prefix(value: str) -> str:
    # Confluence normalizes header IDs: lowercase and remove non-alnum
    out = []
    for ch in value.lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in {"-", "_"}:
            out.append(ch)
    # collapse duplicate hyphens (leave underscores as-is)
    normalized = "".join(out)
    normalized = re.sub(r"-{2,}", "-", normalized).strip("-")
    return normalized


# =============================================================================
#  데이터 클래스
# =============================================================================

@dataclass
class Finding:
    """취약점 항목"""
    id: str
    title: str
    severity: str
    category: str
    subcategory: str
    description: str
    file: str
    line: int
    endpoint: str
    code_snippet: str
    context_before: list
    context_after: list
    recommendation: str
    evidence_type: str  # code, config, api, etc.
    flow: list
    instances: list = field(default_factory=list)
    layer: str = ""
    boundary: str = ""
    sink_class: str = ""
    edge_source: str = ""
    confidence: float | None = None
    unknown_reason: str = ""


@dataclass
class CategoryResult:
    """카테고리별 결과"""
    category_id: str
    category_name: str
    findings: list
    vuln_count: int
    info_count: int
    safe_count: int


# =============================================================================
#  파일 파싱
# =============================================================================

def detect_category(filepath: Path, task_id: str) -> str:
    """파일명/task_id에서 카테고리 추출"""
    fname = filepath.name.lower()
    tid = task_id.lower()

    if "22" in fname or "22" in tid or "injection" in fname:
        return "injection"
    elif "23" in fname or "23" in tid or "xss" in fname:
        return "xss"
    elif "24" in fname or "24" in tid or "file" in fname:
        return "file_handling"
    elif "25" in fname or "25" in tid or "data" in fname:
        return "data_protection"
    elif "26" in fname or "26" in tid or "auth" in fname or "payment" in fname:
        return "auth_payment"
    return "injection"


def normalize_category_id(raw: str | None) -> Optional[str]:
    """finding.category 값을 CATEGORY_INFO 키로 정규화한다."""
    if not raw:
        return None

    val = str(raw).strip().lower()
    if not val:
        return None

    compact = re.sub(r"[\s\\/-]+", "_", val)
    compact = re.sub(r"_+", "_", compact).strip("_")

    alias = {
        "injection": "injection",
        "xss": "xss",
        "file_handling": "file_handling",
        "file": "file_handling",
        "data_protection": "data_protection",
        "data_protect": "data_protection",
        "auth_payment": "auth_payment",
        "auth": "auth_payment",
        "payment": "auth_payment",
        "authz": "auth_payment",
        "authentication": "auth_payment",
        "authorization": "auth_payment",
    }

    if compact in CATEGORY_INFO:
        return compact
    if compact in alias:
        return alias[compact]
    return None


def extract_code_evidence(source_dir: Path, file_path: str, line: int,
                          context_lines: int = 5) -> tuple[str, list, list]:
    """소스 파일에서 코드 증적 추출"""
    if not file_path or not source_dir:
        return "", [], []

    # 파일 경로 정규화
    if file_path.startswith(str(source_dir)):
        full_path = Path(file_path)
    else:
        full_path = source_dir / file_path

    if not full_path.exists():
        # 부분 경로로 검색
        for f in source_dir.rglob("*.kt"):
            if file_path in str(f) or f.name in file_path:
                full_path = f
                break
        for f in source_dir.rglob("*.java"):
            if file_path in str(f) or f.name in file_path:
                full_path = f
                break

    if not full_path.exists():
        return "", [], []

    try:
        lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except:
        return "", [], []

    if line <= 0 or line > len(lines):
        return "", [], []

    idx = line - 1
    code_line = lines[idx]
    before = lines[max(0, idx - context_lines):idx]
    after = lines[idx + 1:min(len(lines), idx + 1 + context_lines)]

    return code_line, before, after


def build_evidence_block(source_dir: Path, file_path: str, line: int,
                         min_lines: int = 10, max_lines: int = 20) -> str:
    """FILE 라인 + 줄번호 스니펫 블록 생성 (10~20줄)"""
    if not file_path or not source_dir or not line:
        return ""

    # 파일 경로 정규화
    if file_path.startswith(str(source_dir)):
        full_path = Path(file_path)
    else:
        full_path = source_dir / file_path

    if not full_path.exists():
        # 부분 경로로 검색
        for f in source_dir.rglob("*.kt"):
            if file_path in str(f) or f.name in file_path:
                full_path = f
                break
        for f in source_dir.rglob("*.java"):
            if file_path in str(f) or f.name in file_path:
                full_path = f
                break

    if not full_path.exists():
        return ""

    try:
        lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return ""

    if line <= 0 or line > len(lines):
        return ""

    # 목표 라인 수 (10~20)
    target = 12
    target = max(min_lines, min(max_lines, target))

    idx = line - 1
    before_max = min(idx, target // 2)
    after_max = min(len(lines) - idx - 1, target - before_max - 1)
    # 부족하면 반대쪽에서 보충
    if before_max + after_max + 1 < target:
        extra = target - (before_max + after_max + 1)
        add_before = min(idx - before_max, extra)
        before_max += add_before
        extra -= add_before
        add_after = min(len(lines) - idx - 1 - after_max, extra)
        after_max += add_after

    start = idx - before_max
    end = idx + after_max

    snippet_lines = []
    for i in range(start, end + 1):
        snippet_lines.append(f"{i+1:4d} │ {lines[i]}")

    file_display = file_path
    if line:
        file_display += f":{line}"

    header = f"**코드 증적:**\n\nFILE: {file_display}\n```\n"
    body = "\n".join(snippet_lines)
    return header + body + "\n```\n"


def load_findings(filepath: Path, source_dir: Path) -> dict[str, list[Finding]]:
    """진단 결과 파일 로드"""
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)

    task_id = data.get("task_id", "")
    fallback_category = detect_category(filepath, task_id)
    glossary = _load_glossary()

    findings_by_category: dict[str, list[Finding]] = {}
    for idx, f in enumerate(data.get("findings", []), 1):
        category = normalize_category_id(f.get("category")) or fallback_category
        cat_info = CATEGORY_INFO[category]

        # 위치 정보 추출
        location = f.get("location", {})
        if isinstance(location, str):
            # 문자열인 경우 파싱
            file_match = re.search(r'([^\s:]+\.(kt|java|js|ts|xml))(?::(\d+))?', location)
            file_path = file_match.group(1) if file_match else ""
            line_num = int(file_match.group(3)) if file_match and file_match.group(3) else 0
            endpoint = f.get("request_mapping", "")
        else:
            file_path = location.get("file", f.get("file", ""))
            line_num = location.get("line", f.get("line", 0))
            endpoint = location.get("endpoint", location.get("api", f.get("request_mapping", "")))

        # affected_files에서 추가 정보
        for af in f.get("affected_files", []):
            if isinstance(af, dict):
                if not file_path:
                    file_path = af.get("file", "")
                if not line_num:
                    line_num = af.get("line", 0)
                if not endpoint:
                    endpoint = af.get("api", af.get("endpoint", ""))

        # affected_file 문자열 파싱 (e.g., "path:line; path:line")
        if not file_path:
            af_str = f.get("affected_file", "")
            if isinstance(af_str, str) and af_str:
                first = af_str.split(";")[0].strip()
                file_match = re.search(r'([^\s:]+\.(kt|java|js|ts|xml))(?::(\d+))?', first)
                if file_match:
                    file_path = file_match.group(1)
                    line_num = int(file_match.group(3)) if file_match.group(3) else line_num

        # 기존 evidence 우선 사용 (민감정보는 redacted evidence를 우선 반영)
        code_snippet = ""
        ctx_before = []
        ctx_after = []
        evidence = f.get("evidence", {})
        if isinstance(evidence, dict):
            code_snippet = evidence.get("code_snippet", evidence.get("code", ""))
            ctx_before = evidence.get("context_before", [])
            ctx_after = evidence.get("context_after", [])

        # 코드 증적 추출 (evidence가 없을 때만)
        if not code_snippet:
            code_snippet, ctx_before, ctx_after = extract_code_evidence(
                source_dir, file_path, line_num
            )

        # 인스턴스 정보 (패턴 기반 다중 위치)
        instances = []
        metadata = f.get("metadata", {})
        meta_instances = metadata.get("instances") if isinstance(metadata, dict) else None
        if isinstance(meta_instances, list):
            for inst in meta_instances:
                if isinstance(inst, dict):
                    inst_file = inst.get("file", "")
                    inst_line = inst.get("line", 0)
                    inst_endpoint = inst.get("endpoint", inst.get("api", ""))
                    instances.append({
                        "file": inst_file,
                        "line": inst_line,
                        "endpoint": inst_endpoint,
                    })
                elif isinstance(inst, str):
                    file_match = re.search(r'([^\s:]+\.(kt|java|js|ts|xml))(?::(\d+))?', inst)
                    inst_file = file_match.group(1) if file_match else ""
                    inst_line = int(file_match.group(3)) if file_match and file_match.group(3) else 0
                    instances.append({
                        "file": inst_file,
                        "line": inst_line,
                        "endpoint": "",
                    })

        if not instances and (file_path or line_num or endpoint):
            instances = [{
                "file": file_path,
                "line": line_num,
                "endpoint": endpoint,
            }]

        # affected_file 문자열 기반 인스턴스 확장
        af_str = f.get("affected_file", "")
        if isinstance(af_str, str) and ";" in af_str:
            extra_instances = []
            for part in af_str.split(";"):
                part = part.strip()
                if not part:
                    continue
                file_match = re.search(r'([^\s:]+\.(kt|java|js|ts|xml))(?::(\d+))?', part)
                if file_match:
                    inst_file = file_match.group(1)
                    inst_line = int(file_match.group(3)) if file_match.group(3) else 0
                    extra_instances.append({
                        "file": inst_file,
                        "line": inst_line,
                        "endpoint": "",
                    })
            # merge unique
            seen = {(i.get("file"), i.get("line")) for i in instances}
            for inst in extra_instances:
                key = (inst.get("file"), inst.get("line"))
                if key not in seen:
                    instances.append(inst)
                    seen.add(key)

        # 서브카테고리 추출
        title_lower = f.get("title", "").lower()
        cat_lower = f.get("category", "").lower()
        subcategory = ""
        # Prefer longer keys first to avoid substring collisions (e.g., nosql vs sql)
        for key in sorted(cat_info["items"].keys(), key=len, reverse=True):
            name = cat_info["items"][key]
            if key in title_lower or key in cat_lower:
                subcategory = name
                break
        if not subcategory:
            subcategory = list(cat_info["items"].values())[0]

        title = _apply_glossary(f.get("title", ""), glossary)
        description = _apply_glossary(f.get("description", ""), glossary)
        recommendation = _apply_glossary(f.get("recommendation", ""), glossary)

        finding = Finding(
            id=f.get("id", ""),
            title=title,
            severity=f.get("severity", "info").lower(),
            category=cat_info["name"],
            subcategory=subcategory,
            description=description,
            file=file_path,
            line=line_num,
            endpoint=endpoint,
            code_snippet=code_snippet,
            context_before=ctx_before if isinstance(ctx_before, list) else [],
            context_after=ctx_after if isinstance(ctx_after, list) else [],
            recommendation=recommendation,
            evidence_type="code" if code_snippet else "description",
            flow=f.get("flow", []),
            instances=instances,
            layer=f.get("layer",""),
            boundary=f.get("boundary",""),
            sink_class=f.get("sink_class",""),
            edge_source=f.get("edge_source",""),
            confidence=f.get("confidence"),
            unknown_reason=f.get("unknown_reason",""),
        )
        findings_by_category.setdefault(category, []).append(finding)

    return findings_by_category


def assign_display_ids(all_findings: dict[str, list[Finding]]) -> None:
    """카테고리별 표시용 ID(예: 4-1, 6-2)를 일관되게 재부여한다."""
    ordered_categories = ["injection", "xss", "file_handling", "data_protection", "auth_payment"]
    for category_id in ordered_categories:
        findings = all_findings.get(category_id) or []
        if not findings:
            continue
        cat_no = CATEGORY_INFO[category_id]["number"]
        for idx, finding in enumerate(findings, 1):
            finding.id = f"{cat_no}-{idx}"


# =============================================================================
#  보고서 생성
# =============================================================================

def generate_summary_table(all_findings: dict[str, list[Finding]]) -> str:
    """진단 결과 요약 표 생성"""
    lines = []
    if ANCHOR_STYLE == "md2cf":
        lines.append("## summary-table\n")
        lines.append("**2. 진단 결과 요약**\n")
    else:
        lines.append("## 2. 진단 결과 요약\n")
        anchor_line = _anchor("summary-table")
        if anchor_line:
            lines.append(anchor_line)
            lines.append("")
    headers = ["No", "점검 구분", "점검 항목", "결과", "위험도", "Request Mapping", "File", "Sink", "Boundary"]
    rows: list[list[str]] = []

    link_pairs = []
    for category_id, findings in all_findings.items():
        for f in findings:
            result, risk = RISK_MAP.get(f.severity, ("정보", 4))
            if result == "양호":
                continue  # 양호 항목은 요약에서 제외

            if len(f.instances) > 1:
                file_short = f"multiple ({len(f.instances)})"
            else:
                file_short = f.file.split("/")[-1] if f.file else "-"
            endpoint = f.endpoint if f.endpoint else "-"

            rows.append([f.id, f.category, f.subcategory, result, str(risk), f"`{endpoint}`", file_short])
            link_pairs.append((f.id, f.subcategory))

    if ANCHOR_STYLE == "md2cf":
        lines.append(_html_table(headers, rows))
        lines.append("")
    else:
        lines.append("| No | 점검 구분 | 점검 항목 | 결과 | 위험도 | Request Mapping | File |")
        lines.append("|:--:|:-------:|:-------:|:---:|:-----:|:----------------|:-----|")
        for row in rows:
            lines.append(
                f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} | "
                f"{row[5]} | {row[6]} |"
            )
        lines.append("")

    if link_pairs and ANCHOR_STYLE != "html":
        lines.append("**상세 링크**")
        for fid, subcat in link_pairs:
            lines.append(f"- {fid} {subcat}: {_anchor_link(f'finding-{fid}', '상세 보기')}")
        lines.append("")

    return "\n".join(lines)


def generate_category_detail(category_id: str, findings: list[Finding],
                             source_dir: Path) -> str:
    """카테고리별 상세 보고서 생성"""
    cat_info = CATEGORY_INFO[category_id]
    lines = []

    # 카테고리 헤더
    lines.append(f"### ({cat_info['number']}) {cat_info['name']}\n")

    # 카테고리 요약 표
    lines.append("| No | 취약점 항목 | 현황 | 결과 | 위험도 | 보안 위협 |")
    lines.append("|:--:|:----------|:-----|:---:|:-----:|:---------|")

    for f in findings:
        result, risk = RISK_MAP.get(f.severity, ("정보", 4))
        # 현황 요약 (description 첫 문장)
        status = f.description.split(".")[0][:50] if f.description else "-"

        lines.append(
            f"| {f.id} | {f.subcategory} | {status}... | {result} | {risk} | {f.endpoint or '-'} | `{f.file or '-'}` | {f.sink_class or '-'} | {f.boundary or '-'} |"
        )

    lines.append("")

    # 각 취약점 상세
    for f in findings:
        result, risk = RISK_MAP.get(f.severity, ("정보", 4))

        lines.append(f"---\n")
        if ANCHOR_STYLE == "md2cf":
            lines.append(f"#### finding-{f.id}\n")
            lines.append(f"**＊ 취약점 {f.id} {f.subcategory} ({result})**\n")
        else:
            lines.append(_anchor(f"finding-{f.id}"))
            lines.append(f"#### ＊ 취약점 {f.id} {f.subcategory} ({result})\n")

        # 영향 받는 엔드포인트/파일
        if f.endpoint:
            lines.append(f"**영향 받는 API:** `{f.endpoint}`\n")
        if f.file:
            file_display = f.file
            if f.line:
                file_display += f":{f.line}"
            lines.append(f"**파일:** `{file_display}`\n")
        lines.append(f"**Facets:** layer=`{f.layer}`, boundary=`{f.boundary}`, sink_class=`{f.sink_class}`")
        if f.edge_source:
            conf = "" if f.confidence is None else f"{f.confidence}"
            lines.append(f"**Edge Source:** `{f.edge_source}` (confidence={conf})")
        if f.unknown_reason:
            lines.append(f"**Unknown Reason:** `{f.unknown_reason}`\n")

        if len(f.instances) > 1:
            if ANCHOR_STYLE == "html":
                lines.append("**전체 인스턴스 목록:** 부록 참조\n")
            else:
                lines.append(f"**전체 인스턴스 목록:** {_anchor_link('appendix-instances', '부록 참조')}\n")
            preview = f.instances[:10]
            preview_items = []
            for inst in preview:
                inst_file = inst.get("file", "-") or "-"
                inst_line = inst.get("line", "-") or "-"
                preview_items.append(f"`{inst_file}:{inst_line}`")
            suffix = ""
            if len(f.instances) > 10:
                suffix = f", ...외 {len(f.instances) - 10}개"
            lines.append(f"**관련 파일(상위 10개):** {', '.join(preview_items)}{suffix}\n")

        # 취약점 설명
        lines.append(f"**설명:**\n")
        lines.append(f"{f.description}\n")

        # 코드 흐름
        if f.flow:
            lines.append("**코드 흐름:**\n")
            if isinstance(f.flow, list):
                for step in f.flow:
                    lines.append(f"- {step}")
                lines.append("")
            else:
                lines.append(f"{f.flow}\n")

        # 코드 증적 (항상 FILE+스니펫 형식으로 자동 포함)
        evidence_blocks = []
        if len(f.instances) > 1:
            for inst in f.instances[:3]:
                evidence_blocks.append(
                    build_evidence_block(source_dir, inst.get("file"), inst.get("line"))
                )
        else:
            evidence_blocks.append(build_evidence_block(source_dir, f.file, f.line))
        for block in evidence_blocks:
            if block:
                lines.append(block)

        # 대응 방안
        if f.recommendation:
            lines.append(f"**대응 방안:**\n")
            lines.append(f"{f.recommendation}\n")

        if ANCHOR_STYLE == "html":
            lines.append("**요약으로 돌아가기:** 진단 결과 요약\n")
        else:
            lines.append(f"**요약으로 돌아가기:** {_anchor_link('summary-table', '진단 결과 요약')}\n")
        lines.append("")

    return "\n".join(lines)


def generate_instance_appendix(all_findings: dict[str, list[Finding]]) -> str:
    """인스턴스 상세 목록 부록 생성 (다중 위치만)"""
    lines = []
    appendix_items = []
    for category_id, findings in all_findings.items():
        for f in findings:
            if len(f.instances) > 1:
                appendix_items.append(f)

    if not appendix_items:
        return ""

    if ANCHOR_STYLE == "md2cf":
        lines.append("## appendix-instances\n")
        lines.append("**4. 부록: 인스턴스 상세 목록**\n")
    else:
        lines.append("## 4. 부록: 인스턴스 상세 목록\n")
        anchor_line = _anchor("appendix-instances")
        if anchor_line:
            lines.append(anchor_line)
    for f in appendix_items:
        lines.append(f"### {f.id} {f.subcategory}\n")
        lines.append("| File | Line | Endpoint |")
        lines.append("|:-----|:----:|:---------|")
        for inst in f.instances:
            inst_file = inst.get("file", "-") or "-"
            inst_line = inst.get("line", "-") or "-"
            inst_endpoint = inst.get("endpoint", "-") or "-"
            lines.append(f"| `{inst_file}` | {inst_line} | `{inst_endpoint}` |")
        lines.append("")
    if ANCHOR_STYLE == "html":
        lines.append("**요약으로 돌아가기:** 진단 결과 요약\n")
    else:
        lines.append(f"**요약으로 돌아가기:** {_anchor_link('summary-table', '진단 결과 요약')}\n")

    return "\n".join(lines)


def generate_report(
    source_dir: Path,
    finding_files: list[Path],
    output_file: Path,
    service_name: str,
    target_modules: list[str] = None,
    repo: Optional[str] = None,
    branch: Optional[str] = None,
    commit: Optional[str] = None,
    domain: Optional[str] = None,
    source_label: Optional[str] = None,
    anchor_style: Optional[str] = None,
    anchor_prefix: Optional[str] = None,
):
    """최종 보고서 생성"""
    global ANCHOR_STYLE, ANCHOR_PREFIX
    if anchor_style:
        ANCHOR_STYLE = anchor_style
    if anchor_prefix:
        ANCHOR_PREFIX = _normalize_anchor_prefix(anchor_prefix) if ANCHOR_STYLE == "md2cf" else anchor_prefix

    today = date.today().strftime("%Y.%m.%d")

    # Findings 로드
    all_findings: dict[str, list[Finding]] = {}
    for fpath in finding_files:
        loaded = load_findings(fpath, source_dir)
        total_in_file = 0
        split_info = []
        for category_id, findings in loaded.items():
            all_findings.setdefault(category_id, []).extend(findings)
            total_in_file += len(findings)
            split_info.append(f"{category_id}:{len(findings)}")
        split_text = ", ".join(split_info) if split_info else "none"
        print(f"  {fpath.name}: {total_in_file}건 ({split_text})")

    # task 파일 내부에 카테고리가 섞여 있어도 표시 ID를 카테고리별로 일관 재부여
    assign_display_ids(all_findings)

    # 통계
    total_vuln = sum(
        sum(1 for f in findings if RISK_MAP.get(f.severity, ("", 0))[0] == "취약")
        for findings in all_findings.values()
    )
    total_info = sum(
        sum(1 for f in findings if RISK_MAP.get(f.severity, ("", 0))[0] == "정보")
        for findings in all_findings.values()
    )

    # 보고서 작성
    report_lines = []

    # 제목
    report_lines.append(f"# [보안진단] {service_name} 보안진단 결과\n")

    # 서비스 개요
    report_lines.append("## 1. 서비스 개요\n")
    report_lines.append(f"**진단 대상:** {service_name}\n")
    report_lines.append(f"**진단 일자:** {today}\n")
    report_lines.append(f"**소스 경로:** `{source_label or source_dir}`\n")
    if repo:
        report_lines.append(f"**레포:** `{repo}`\n")
    if branch:
        report_lines.append(f"**브랜치:** `{branch}`\n")
    if commit:
        report_lines.append(f"**커밋:** `{commit}`\n")
    if domain:
        report_lines.append(f"**도메인:** `{domain}`\n")
    if target_modules:
        report_lines.append(f"**대상 모듈:** {', '.join(target_modules)}\n")
    report_lines.append("")

    # 진단 결과 요약
    report_lines.append("### 1.1 진단 결과 통계\n")
    report_lines.append(f"- **취약:** {total_vuln}건")
    report_lines.append(f"- **정보:** {total_info}건")
    report_lines.append("")

    if total_vuln > 0 or total_info > 0:
        report_lines.append("### 1.2 주요 식별 취약점\n")
        # 주요 취약점 요약 (High/Critical만)
        for category_id, findings in all_findings.items():
            high_findings = [f for f in findings if f.severity in ("critical", "high")]
            if high_findings:
                cat_info = CATEGORY_INFO[category_id]
                report_lines.append(f"**{cat_info['name']}**")
                for f in high_findings[:3]:  # 상위 3개만
                    report_lines.append(f"- {f.title}")
                report_lines.append("")

    # 의심 후보 (예: SQLi)
    suspected_items = []
    for fpath in finding_files:
        try:
            raw = json.loads(fpath.read_text(encoding="utf-8"))
        except Exception:
            continue
        meta = raw.get("metadata", {}) if isinstance(raw, dict) else {}
        candidates = meta.get("suspected_candidates", [])
        if candidates:
            for cand in candidates:
                file_ref = cand.get("file", "-") or "-"
                reason = cand.get("reason", "-") or "-"
                suspected_items.append((file_ref, reason))

    if suspected_items:
        report_lines.append("### 1.3 의심 후보 (재검증 필요)\n")
        for file_ref, reason in suspected_items:
            report_lines.append(f"- `{file_ref}` — {reason}")
        report_lines.append("")

    # 요약 표
    report_lines.append(generate_summary_table(all_findings))

    # 카테고리별 상세
    report_lines.append("## 3. 진단 결과 상세\n")

    for category_id in ["injection", "xss", "file_handling", "data_protection", "auth_payment"]:
        if category_id in all_findings and all_findings[category_id]:
            report_lines.append(
                generate_category_detail(category_id, all_findings[category_id], source_dir)
            )

    # 부록 (다중 인스턴스 목록)
    appendix = generate_instance_appendix(all_findings)
    if appendix:
        report_lines.append(appendix)

    # 파일 저장
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print(f"\n보고서 저장: {output_file}")
    print(f"  총 {total_vuln + total_info}건의 취약점/정보 항목 포함")


# =============================================================================
#  메인
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="취약점 진단 결과 상세 보고서 생성 (Markdown)"
    )
    parser.add_argument(
        "source_dir",
        help="진단 대상 소스코드 디렉토리 (코드 증적 추출용)",
    )
    parser.add_argument(
        "finding_results",
        nargs="+",
        help="Task 2-2~2-6 취약점 진단 결과 JSON 파일들",
    )
    parser.add_argument(
        "--output", "-o",
        help="출력 Markdown 파일 경로",
        default="진단결과_보고서.md",
    )
    parser.add_argument(
        "--service", "-s",
        help="서비스명",
        default="서비스명",
    )
    parser.add_argument(
        "--modules", "-m",
        nargs="*",
        help="대상 모듈 필터 (예: pcona-console)",
        default=None,
    )
    parser.add_argument(
        "--repo",
        help="레포 정보 (예: http://git.example.com/org/repo.git)",
        default=None,
    )
    parser.add_argument(
        "--branch",
        help="브랜치명",
        default=None,
    )
    parser.add_argument(
        "--commit",
        help="커밋 해시",
        default=None,
    )
    parser.add_argument(
        "--domain",
        help="도메인 정보",
        default=None,
    )
    parser.add_argument(
        "--source-label",
        help="보고서에 표시할 소스 경로/URL (증적 추출 경로와 분리)",
        default=None,
    )
    parser.add_argument(
        "--anchor-style",
        help="Anchor 출력 형식 (confluence|html|md2cf). md2cf 사용 시 md2cf 권장.",
        default="confluence",
        choices=["confluence", "html", "md2cf"],
    )
    parser.add_argument(
        "--anchor-prefix",
        help="Confluence 헤더 앵커 prefix (예: 페이지 제목). md2cf에서 링크를 #<prefix>-<name> 형태로 생성.",
        default=None,
    )
    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        print(f"Error: 소스 디렉토리를 찾을 수 없습니다: {source_dir}")
        sys.exit(1)

    finding_files = []
    for fpath in args.finding_results:
        p = Path(fpath)
        if p.exists():
            finding_files.append(p)
        else:
            print(f"Warning: 파일을 찾을 수 없습니다: {fpath}")

    if not finding_files:
        print("Error: 취약점 진단 결과 파일이 없습니다.")
        sys.exit(1)

    if not args.source_label:
        print("Error: --source-label 값이 필요합니다. (예: repo URL 또는 사용자 표시 경로)")
        sys.exit(1)

    if args.anchor_style == "confluence":
        print(
            "Warning: --anchor-style confluence는 [[ANCHOR:...]] 토큰을 출력합니다. "
            "Confluence 에디터에 Markdown을 직접 복사/붙여넣기 하면 토큰이 텍스트로 노출될 수 있습니다. "
            "복붙/변환 경로에서는 --anchor-style md2cf --anchor-prefix <PageTitle> 사용을 권장합니다."
        )
    if args.anchor_style == "md2cf" and not args.anchor_prefix:
        print(
            "Warning: --anchor-style md2cf에 --anchor-prefix가 없으면 Confluence 헤더 id prefix와 "
            "내부 링크가 불일치할 수 있습니다. 페이지 제목(정확히 동일)으로 --anchor-prefix를 지정하세요."
        )

    print(f"소스 디렉토리: {source_dir}")
    generate_report(
        source_dir,
        finding_files,
        Path(args.output),
        args.service,
        args.modules,
        args.repo,
        args.branch,
        args.commit,
        args.domain,
        args.source_label,
        args.anchor_style,
        args.anchor_prefix,
    )


if __name__ == "__main__":
    main()
