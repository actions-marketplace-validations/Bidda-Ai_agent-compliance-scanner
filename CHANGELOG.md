# Changelog

## [0.1.6] - 2026-07-16

### Changed
- Documentation refresh. README badge, intro, and footer updated to the live registry size of 10,065 source-verified regulatory nodes across 39 sovereign pillars (was 9,762 / 39).

### Notes
- Documentation-only update. Pattern detection logic is unchanged (same 12 AI/agent patterns from 0.1.0).

## [0.1.5] - 2026-06-22

### Changed
- Documentation refresh. README badge, intro, and footer updated to the live registry size of 9,762 source-verified regulatory nodes across 39 sovereign pillars (was 8,700 / 39).

### Notes
- Documentation-only update. Pattern detection logic is unchanged (same 12 AI/agent patterns from 0.1.0).
- The in-product PR-comment footer count in `scanner.cjs` is aligned separately in the next code release.

## [0.1.4] - 2026-06-03

### Changed
- Registry coverage bumped to **8,700 cryptographically-signed regulatory nodes across 39 sovereign pillars** (was 7,766 / 34). Reflects ongoing daily node generation, source-watcher amendments, and the addition of Data Protection & Privacy, Trade Compliance & Export Controls, Financial Crime AML & Sanctions, and Public Sector & Government Procurement pillars.
- README badge, intro, footer, and the PR comment template (`scanner.cjs`) all updated to the live count.

### Notes
- Pattern detection logic is unchanged - same 12 AI/agent patterns from 0.1.0.
- Bidda discovery API contract is stable; the scanner continues to call `bidda.com/api/v1/nodes/index.json` with no auth.

## [0.1.3] - 2026-05-26

### Changed
- Registry count update: 5,835 → 7,766 nodes (Sprints K + M + thin-pillar fills).

## [0.1.2] - 2026-05-01

### Fixed
- Trim action description to 125 chars for the GitHub Marketplace listing.

## [0.1.1] - 2026-04-30

### Changed
- Registry count update: 3,543 → 3,680 → 5,835 nodes (Sprint K + M accepted).

## [0.1.0] - 2026-04-28

Initial public release. MVP scope.

### Added
- Composite GitHub Action with 7 configurable inputs (`api-url`, `paths`, `domains`, `severity`, `max-nodes`, `fail-on`, `github-token`)
- Pure-Node scanner with zero npm dependencies (only Node 20 stdlib)
- 12 AI/agent code patterns:
  - LangChain / CrewAI / AutoGen / Pydantic AI imports
  - OpenAI-style and Anthropic-style system prompts
  - MCP tool definitions (`@mcp.tool`, `FastMCP`)
  - Biometric identification (EU AI Act Annex III high-risk)
  - HR / resume scoring (NYC LL 144 + EU AI Act)
  - Credit decisioning (GDPR Art 22 + ECOA + EU AI Act)
  - Web scraping / browser automation
  - Critical/production third-party ICT usage (DORA Art 28)
- Bidda discovery API integration - relevant compliance nodes surfaced per pattern
- Idempotent PR comment (updates the same comment on each push, never spams)
- Advisory by default (`fail-on: never`); opt-in blocking via `fail-on: warn` or `block`
- Suppression via `[skip-bidda]` in PR description
- MIT license

### Privacy
- All pattern matching is local to the GitHub-hosted runner.
- Calls only the public Bidda discovery API (`bidda.com/api/v1/nodes/index.json`) - no auth, no PII.
- Diff content, prompts, repo contents are **never** transmitted off the runner.
