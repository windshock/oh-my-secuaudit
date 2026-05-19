# Migration: `F-ARCH-NNN` → `FINDING-NNN`

Per [ADR-0004](../decisions/0004-finding-id-namespace.md), finding identifiers are unified under the `FINDING-NNN` namespace. Architecture-review-originated findings historically used the `F-ARCH-NNN` prefix and are migrated lazily — when a review is re-run or amended, its findings are renumbered then.

This file tracks the inventory and mapping.

## Policy

- `F-ARCH-NNN` remains a valid identifier in `SPR.linked_findings` for one release cycle (backward compat).
- New audits issue `FINDING-NNN` IDs from the start. The originating skill is recorded in finding metadata as `metadata.source_skill = security-architecture-review`.
- When a review is re-run, existing `F-ARCH-NNN` IDs are renumbered to `FINDING-NNN` in the same PR, and `SPR.linked_findings` references are updated.
- No retroactive renumbering of reviews that are not being amended.

## Inventory (as of 2026-05-19)

Each row is a legacy finding ID, the originating review, and the target FINDING-NNN slot (assigned at migration time, not pre-allocated globally).

### shoppingtab review

| Legacy ID | Title (short) | Target ID | Status |
|---|---|---|---|
| F-ARCH-001 | 무인증 추천 배치 재생성 | TBD | not-migrated |
| F-ARCH-002 | 배치 ACL 불일치 | TBD | not-migrated |
| F-ARCH-003 | 저장소 내 비밀값 노출 | TBD | not-migrated |
| F-ARCH-004 | 관리자 RBAC 기본 읽기 권한 기반 쓰기 노출 | TBD | not-migrated |
| F-ARCH-005 | webview 제어평면의 네이티브 쿼리 콘솔 | TBD | not-migrated |
| F-ARCH-006 | 공동구매 자산성 API 14개 엔드포인트 | TBD | not-migrated |
| F-ARCH-007 | XSSStringSerializer 콘텐츠 무결성 | TBD | not-migrated |

### ogog review

| Legacy ID | Title (short) | Target ID | Status |
|---|---|---|---|
| F-ARCH-001 | Secret and crypto material in repo | TBD | not-migrated |
| F-ARCH-002 | Automated abuse / high-risk transaction controls | TBD | not-migrated |
| F-ARCH-003 | OAuth revoke / partner baseline gaps | TBD | not-migrated |
| F-ARCH-004 | Privileged control plane identity gaps | TBD | not-migrated |
| F-ARCH-005 | Regression gates for historical findings | TBD | not-migrated |
| F-ARCH-006 | Internal/batch ACL alignment | TBD | not-migrated |
| F-ARCH-007 | Pay widget origin / iframe trust | TBD | not-migrated |

### fidosvr review

No `F-ARCH-NNN` identifiers were issued; the review uses inline references. No migration required.

### gifticon analysis

Already on `FINDING-NNN` namespace (FINDING-001 through FINDING-007). No migration required, but per [ADR-0002](../decisions/0002-cluster-vs-finding.md), `FINDING-002` (309 endpoints needs-review enumeration) is a misfiled cluster artifact and should be relocated to sec-cluster's `CLUSTERS.md` output. Tracked separately.

## Status values

- `not-migrated` — legacy ID still in use; no replacement issued.
- `mapped` — target FINDING-NNN ID allocated; review document not yet updated.
- `migrated` — review document updated, `SPR.linked_findings` updated, legacy ID retired.

## Execution

Migration happens per-project when the project is next re-audited. No mass-rewrite is scheduled. This file is updated when individual rows progress.
