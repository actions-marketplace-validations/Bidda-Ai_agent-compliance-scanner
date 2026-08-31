# Bidda Agent Compliance Scanner

[![Bidda](https://img.shields.io/badge/Bidda-10,000%2B%20regulatory%20nodes-blue)](https://bidda.com)
[![CISA Secure by Design](https://img.shields.io/badge/CISA-Secure%20by%20Design%20Pledge-blue)](https://bidda.com/cisa/secure-by-design)
[![bidda-mcp MCP server](https://glama.ai/mcp/servers/Bidda-Ai/bidda-mcp/badges/score.svg)](https://glama.ai/mcp/servers/Bidda-Ai/bidda-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Zero-config GitHub Action that scans AI agent code on every PR for regulatory compliance considerations** - against the [Bidda Sovereign Intelligence](https://bidda.com) registry of 10,100+ cryptographically-signed regulatory nodes across 39 sovereign pillars (EU AI Act, DORA, GDPR, NIS2, FERPA, FDA SaMD, NIST AI RMF, ISO/IEC 42001, MITRE ATT&CK/ATLAS/D3FEND/CAPEC, and more).

> **Advisory only by default.** This Action will never block your PR. It posts a single comment listing relevant compliance nodes the team should review. Detailed remediation logic is available via Bidda's $0.01 USDC unlock (L402/x402) or Skyfire bearer token.

---

## Why this exists

Every AI agent your team ships is a regulatory exposure. The EU AI Act takes effect on high-risk systems on **2 August 2026**. DORA enforcement is **already live** as of January 2025. NYC Local Law 144 bias audits are **already enforceable**. Most engineering teams find out about applicable regulations *after* the fine.

This Action scans your PRs for AI/agent code patterns - LangChain imports, system prompts, biometric identifiers, credit-decisioning code, MCP tool definitions - and surfaces the specific Bidda compliance nodes you should review **before** merging.

## Quick start

Add to `.github/workflows/bidda-compliance.yml` in your repo:

```yaml
name: Bidda Agent Compliance
on:
  pull_request:
    branches: [main]

permissions:
  pull-requests: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Bidda-Ai/agent-compliance-scanner@v0
```

That's it. On the next PR, you'll get a comment like this:

> 🛡️ **Bidda Agent Compliance Scanner**
>
> Detected 2 AI/agent code pattern(s) in this PR. Below are relevant compliance nodes from the Bidda registry - advisory only.
>
> ### `langchain-import`
> **Detected in:** `src/agents/sales_agent.py`
> LangChain agent code detected - review against AI Governance compliance nodes.
>
> **Relevant compliance nodes:**
> - [`eu-ai-act-article-14-human-oversight`](https://bidda.com/nodes/eu-ai-act-article-14-human-oversight) - EU AI Act Article 14 - Human Oversight
>   > High-risk AI systems must be designed and developed in such a way that they can be effectively overseen by natural persons during the period in which they are in use…
>   - Free metadata: https://bidda.com/api/v1/nodes/eu-ai-act-article-14-human-oversight
>   - Full deterministic workflow ($0.01 unlock): https://bidda.com/api/v1/vault/nodes/eu-ai-act-article-14-human-oversight
>
> ### `credit-scoring`
> **Detected in:** `src/lending/decision.py`
> AI credit decisioning detected - GDPR Art 22 + ECOA + EU AI Act high-risk apply.
>
> **Relevant compliance nodes:** *(...)*

## Configuration

```yaml
- uses: Bidda-Ai/agent-compliance-scanner@v0
  with:
    # Bidda API base URL (default: https://bidda.com/api/v1)
    api-url: 'https://bidda.com/api/v1'

    # Glob patterns to scan (default: all changed files in the PR)
    paths: |
      src/**/*.py
      apps/**/*.ts

    # Comma-separated Bidda domains to prioritise (default: auto-detect)
    domains: 'AI Governance & Law,Cybersecurity,Banking & Global Finance'

    # Severity surface - info | warn | block (default: warn)
    severity: 'warn'

    # Maximum compliance nodes to surface in the comment (default: 8)
    max-nodes: '8'

    # When to fail the action - never | warn | block (default: never; advisory only)
    fail-on: 'never'
```

### Outputs

| Output | Description |
|---|---|
| `matched-nodes` | JSON array of Bidda `node_id`s surfaced for this PR |
| `agent-patterns-found` | Number of AI agent code patterns detected in the diff |

## What it detects

| Pattern | Triggers on | Compliance domains |
|---|---|---|
| `langchain-import` | `from langchain` / `import { … } from 'langchain'` | AI Governance |
| `crewai-import` | `from crewai` / multi-agent CrewAI usage | AI Governance |
| `autogen-import` | `from autogen` / Microsoft AutoGen usage | AI Governance |
| `pydantic-ai-import` | `from pydantic_ai` | AI Governance |
| `openai-system-prompt` | OpenAI message-array `role: system` | AI Governance |
| `anthropic-system` | Anthropic SDK `system=` parameter | AI Governance |
| `mcp-tool-definition` | `@mcp.tool` / `FastMCP` / MCP server def | AI Governance + Cybersecurity |
| `biometric-identification` | face / facial recognition libraries | AI Governance (EU AI Act Annex III high-risk) |
| `hr-screening` | resume scoring / candidate ranking | AI Governance + Workplace (NYC LL 144) |
| `credit-scoring` | credit decisioning / loan approval | AI Governance + Banking (GDPR Art 22, ECOA) |
| `web-scraping` | BeautifulSoup / Playwright / Puppeteer | Legal & IP + AI Governance |
| `financial-ict-third-party` | critical/prod usage of cloud/API providers | Banking + Cybersecurity (DORA Art 28) |

Patterns are kept tight on purpose. **Better to miss an issue than false-flag** - false positives destroy trust faster than missed catches build it.

## Privacy & data flow

- The Action runs on your GitHub-hosted runner.
- It calls the public Bidda discovery API (`/api/v1/nodes/index.json`) - no auth, no PII.
- It does **not** send your code, prompts, diffs, or repo contents to any external service.
- Pattern matching is local to the runner; only the `pattern_id` (e.g., `"langchain-import"`) and a domain filter are used to query Bidda.
- The PR comment is posted via the GitHub API using the workflow's built-in `github.token`.

## Suppressing the comment for a PR

Add this anywhere in the PR description:

```
[skip-bidda]
```

Or set `severity: 'info'` on a PR-conditional workflow.

## Roadmap (v0.x → v1)

- v0.1 (current) - pattern scanning + advisory PR comment
- v0.2 - paid pre-merge unlock for full deterministic_workflow per matched node, gated by Skyfire bearer token in repo secrets
- v0.3 - annotations on the actual diff lines (not just summary comment)
- v0.4 - Bidda CLI subcommand: `bidda scan path/to/agent.py` for local pre-commit usage
- v0.5 - language-specific detectors (Python AST, TypeScript AST) replacing regex pattern matching
- v1.0 - opt-in blocking mode with a "compliance gate" rule set per organisation

## License

MIT

## Built by

[Bidda Sovereign Intelligence](https://bidda.com) - 10,100+ cryptographically-signed, primary-source-verified regulatory nodes across 39 sovereign pillars for autonomous AI agents. $0.01 USDC per unlock via L402/x402, or Skyfire bearer for enterprise.

Bidda is a public signatory of the [CISA Secure by Design Pledge](https://bidda.com/cisa/secure-by-design) and publishes a [CISA Cybersecurity Performance Goals crosswalk](https://bidda.com/cisa/cpg-crosswalk) mapping its registry to CISA's CPGs.

Pull requests welcome.
