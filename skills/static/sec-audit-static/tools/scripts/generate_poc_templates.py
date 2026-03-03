#!/usr/bin/env python3
"""
Generate PoC templates (best‑effort) from finding JSON.

Outputs a markdown file with one section per finding, including a curl skeleton
for the recorded request_mapping and placeholders for auth/body.

This does NOT execute anything; it is meant to be filled in during manual/CI runs.
"""
import argparse
import json
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("findings_json", help="task_*_result.json path")
    ap.add_argument("--output", "-o", default="poc_templates.md")
    args = ap.parse_args()

    data = json.load(open(args.findings_json, encoding="utf-8"))
    findings = data.get("findings", [])

    lines = []
    lines.append("# PoC Templates (best-effort)")
    lines.append("")
    lines.append("> 생성 규칙: SKILL poc_policy.md (JUnit5 우선, 불가 시 수동 curl) 기반. 현재는 수동/자동 선택 전 단계이므로 curl 골격만 제공합니다.")
    lines.append("")
    for f in findings:
        rid = f.get("id", "UNKNOWN")
        title = f.get("title", "")
        path = f.get("request_mapping") or "<request_mapping 미기록>"
        severity = f.get("severity", "")
        lines.append(f"## {rid} — {title} ({severity})")
        lines.append("")
        lines.append("고려 대상:")
        lines.append(f"- request_mapping: `{path}`")
        loc = f.get("location", {})
        lines.append(f"- code: `{loc.get('file','')}`:{loc.get('line','')}")
        lines.append(f"- flow: {f.get('flow') or 'N/A'}")
        lines.append("")
        lines.append("실행 스텁 (수동 실행용 curl 템플릿):")
        lines.append("```bash")
        lines.append("# TODO: BASE_URL, AUTH 토큰, 메서드/바디를 채워 넣으세요.")
        lines.append(f"curl -i -k -X POST \"$BASE_URL{path}\" \\")
        lines.append("  -H \"Content-Type: application/json\" \\")
        lines.append("  -H \"Authorization: Bearer $TOKEN\" \\")
        lines.append("  -d '{\"payload\":\"REPLACE\"}'")
        lines.append("```")
        lines.append("")
        lines.append("자동 PoC 대상 설정 가이드:")
        lines.append("- JUnit5/MockMvc 가능 시: 해당 controller/service에 대한 통합 테스트 생성")
        lines.append("- Playwright/ZAP는 필요 시 웹/런타임 제공 후 적용")
        lines.append("")
    Path(args.output).write_text("\n".join(lines), encoding="utf-8")
    print(f"written: {args.output}")


if __name__ == "__main__":
    main()
