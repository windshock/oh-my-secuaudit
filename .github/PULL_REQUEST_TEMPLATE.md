<!--
PR 템플릿 (lean). 모든 섹션을 빈약하게라도 채워야 CI/리뷰가 가벼워짐.
대규모 리팩토 / 컨트랙트 변경 시에는 본문에 ADR / migration 노트도 함께.
-->

## Affected skill(s)

<!-- 어떤 스킬을 건드렸는지. 컨트랙트만 만진 경우 "contracts only" 가능. -->

- [ ] sec-audit-static
- [ ] sec-audit-dast
- [ ] sec-cluster
- [ ] external-software-analysis
- [ ] security-architecture-review
- [ ] security-testing-as-code
- [ ] contracts / docs / CI only

## Contract impact

<!-- 한 줄: none / additive / breaking. breaking인 경우 ADR 링크 + migration 노트 필수. -->

- [ ] None — 스킬 내부 변경, 외부 ABI 미변경
- [ ] Additive — 새 optional 필드, 새 ADR-only enum 값, 새 스킬 자체
- [ ] Breaking — required 필드 추가/삭제, enum 축소, 산출물 모양 변경 → ADR + `docs/migration/` 노트 링크

`docs/contracts/README.md`의 진화 정책을 따랐는가? Yes / No

## Validation evidence

<!-- 변경이 정말 안전한지 어떤 증거로 확인했나. 모든 PR에 최소 한 줄. -->

- [ ] `python3 scripts/validate_skills_repo.py` 통과
- [ ] 스킬 출력 샘플(이전/이후) 비교 — 경로:
- [ ] 새 schema이면 예시 instance가 jsonschema validate 통과
- [ ] (선택) 다운스트림 스킬에서 산출물 소비 시뮬레이션
