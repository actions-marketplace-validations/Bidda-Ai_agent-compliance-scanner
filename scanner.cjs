#!/usr/bin/env node
/**
 * Bidda Agent Compliance Scanner — GitHub Action MVP
 *
 * Runs on a PR. Scans changed files for AI agent code patterns
 * (LangChain, CrewAI, AutoGen, Pydantic AI, OpenAI SDK system prompts,
 * MCP server definitions, etc.). For each detected pattern, queries the
 * Bidda discovery API for relevant compliance nodes and posts a PR comment
 * listing the top matches.
 *
 * DESIGN PRINCIPLES (read before changing):
 *  - ADVISORY by default. Never block a PR unless the user explicitly opts in.
 *    Trust must be earned; one false-positive that blocks a release destroys it.
 *  - Discovery-tier only. The action is free; it never holds a paywall token.
 *    Detailed remediation lives behind the L402 unlock — that's the business model.
 *  - Pattern matches must be tight. Better to miss an issue than false-flag.
 *  - Every comment is signed with a node_id and a deep link to the public node page.
 *  - Zero npm dependencies — runs on Node 20 stdlib only. Faster install, smaller
 *    attack surface, easier to audit.
 *  - Idempotent. Updates the same comment on each push; never spams the PR thread.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const url = require('url');

// ─── Config from action.yml inputs (env vars) ─────────────────────────────────
const API_URL    = process.env.BIDDA_API_URL    || 'https://bidda.com/api/v1';
const PATHS_RAW  = process.env.BIDDA_PATHS      || '';
const DOMAINS    = (process.env.BIDDA_DOMAINS   || '').split(',').map(s => s.trim()).filter(Boolean);
const SEVERITY   = process.env.BIDDA_SEVERITY   || 'warn';
const MAX_NODES  = parseInt(process.env.BIDDA_MAX_NODES || '8', 10);
const FAIL_ON    = process.env.BIDDA_FAIL_ON    || 'never';
const GH_TOKEN   = process.env.GITHUB_TOKEN     || '';
const GH_EVENT   = process.env.GITHUB_EVENT_PATH;
const GH_REPO    = process.env.GITHUB_REPOSITORY;

const COMMENT_MARKER = '<!-- bidda-compliance-scanner -->';

// ─── Pattern library — kept tight to avoid false positives ───────────────────
//
// Each pattern has:
//   id:           short identifier
//   regex:        compiled regex
//   domains:      Bidda domains relevant to this pattern (used to scope API queries)
//   keywords:     terms used to search the Bidda registry for relevant nodes
//   description:  one-liner shown in the PR comment
//
const PATTERNS = [
  // — AI agent frameworks —
  {
    id: 'langchain-import',
    regex: /\b(?:from\s+langchain|import\s+\{?[^}]*\}?\s+from\s+['"]langchain|require\(['"]langchain)/,
    domains: ['AI Governance & Law'],
    keywords: ['LangChain', 'AI agent', 'autonomous'],
    description: 'LangChain agent code detected — review against AI Governance compliance nodes.',
  },
  {
    id: 'crewai-import',
    regex: /\b(?:from\s+crewai|import\s+\{?[^}]*\}?\s+from\s+['"]crewai|require\(['"]crewai)/,
    domains: ['AI Governance & Law'],
    keywords: ['CrewAI', 'multi-agent', 'autonomous'],
    description: 'CrewAI multi-agent code detected.',
  },
  {
    id: 'autogen-import',
    regex: /\b(?:from\s+autogen|import\s+\{?[^}]*\}?\s+from\s+['"]autogen|require\(['"](pyautogen|autogen))/,
    domains: ['AI Governance & Law'],
    keywords: ['AutoGen', 'multi-agent'],
    description: 'AutoGen multi-agent code detected.',
  },
  {
    id: 'pydantic-ai-import',
    regex: /\b(?:from\s+pydantic_ai|import\s+\{?[^}]*\}?\s+from\s+['"]pydantic-ai|require\(['"]pydantic-ai)/,
    domains: ['AI Governance & Law'],
    keywords: ['Pydantic AI', 'agent'],
    description: 'Pydantic AI agent code detected.',
  },
  // — Direct LLM providers (system prompts often live here) —
  {
    id: 'openai-system-prompt',
    regex: /["']role["']\s*:\s*["']system["']/,
    domains: ['AI Governance & Law'],
    keywords: ['system prompt', 'AI transparency'],
    description: 'OpenAI-style system prompt detected — verify transparency disclosures and human oversight.',
  },
  {
    id: 'anthropic-system',
    regex: /\bsystem\s*=\s*["']|\bsystem\s*:\s*["']/,
    domains: ['AI Governance & Law'],
    keywords: ['system prompt', 'AI'],
    description: 'Anthropic-style system parameter detected.',
  },
  // — MCP server / tool exposure —
  {
    id: 'mcp-tool-definition',
    regex: /(?:^|\W)(?:@mcp\.tool|MCP\s*Server|@server\.tool|FastMCP)/m,
    domains: ['AI Governance & Law', 'Cybersecurity'],
    keywords: ['MCP', 'tool', 'agent authentication'],
    description: 'MCP tool/server definition detected — review against agent authorisation nodes.',
  },
  // — High-risk AI use cases (Annex III of EU AI Act) —
  {
    id: 'biometric-identification',
    regex: /\b(?:face_recognition|facial_recognition|biometric_identification|FaceNet|DeepFace)\b/,
    domains: ['AI Governance & Law'],
    keywords: ['biometric', 'high-risk AI', 'EU AI Act'],
    description: 'Biometric identification code detected — likely high-risk AI under EU AI Act Annex III.',
  },
  {
    id: 'hr-screening',
    regex: /\b(?:resume_scor|cv_scor|candidate_rank|hiring_decision|applicant_rank)/i,
    domains: ['AI Governance & Law', 'Workplace'],
    keywords: ['employment AI', 'algorithmic hiring', 'EU AI Act high-risk', 'NYC Local Law 144'],
    description: 'AI-driven hiring/screening detected — high-risk under EU AI Act + NYC LL 144 bias audit applies.',
  },
  {
    id: 'credit-scoring',
    regex: /\b(?:credit_scor|credit_decision|loan_approval|creditworthiness)/i,
    domains: ['AI Governance & Law', 'Banking & Global Finance'],
    keywords: ['credit scoring', 'ECOA', 'GDPR Article 22', 'high-risk AI'],
    description: 'AI credit decisioning detected — GDPR Art 22 + ECOA + EU AI Act high-risk apply.',
  },
  // — Data scraping & web access (GDPR/DPDPA risk) —
  {
    id: 'web-scraping',
    regex: /\b(?:WebScraper|BeautifulSoup|playwright\.|puppeteer\.|requests\.get\([^)]*['"]https?)/,
    domains: ['Legal & IP Sovereignty', 'AI Governance & Law'],
    keywords: ['web scraping', 'GDPR', 'data minimisation', 'TDM exception'],
    description: 'Web scraping / browser automation detected — review GDPR + EU AI Act + national TDM exceptions.',
  },
  // — DORA-relevant code patterns (financial entities only) —
  {
    id: 'financial-ict-third-party',
    regex: /\b(?:azure|aws|gcp|cloudflare|datadog|stripe|plaid)\b.*\b(?:critical|production|prod)/i,
    domains: ['Banking & Global Finance', 'Cybersecurity'],
    keywords: ['DORA', 'ICT third-party', 'critical function'],
    description: 'Critical/production third-party ICT service usage — DORA Article 28 + RTS 2024/1773 apply if you are an EU financial entity.',
  },
];

// ─── HTTP helpers ─────────────────────────────────────────────────────────────
function httpGet(targetUrl, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed = url.parse(targetUrl);
    const req = https.request({
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.path,
      method: 'GET',
      headers: { 'User-Agent': 'BiddaComplianceScanner/0.1', 'Accept': 'application/json', ...headers },
      timeout: 15000,
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout fetching ${targetUrl}`)); });
    req.end();
  });
}

async function httpPost(targetUrl, payload, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed = url.parse(targetUrl);
    const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
    const req = https.request({
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.path,
      method: 'POST',
      headers: {
        'User-Agent': 'BiddaComplianceScanner/0.1',
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        ...headers,
      },
      timeout: 20000,
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout POSTing ${targetUrl}`)); });
    req.write(data);
    req.end();
  });
}

// ─── GitHub API helpers ───────────────────────────────────────────────────────
function ghApi(method, path, body) {
  if (!GH_TOKEN) throw new Error('GITHUB_TOKEN missing');
  const targetUrl = `https://api.github.com${path}`;
  const headers = {
    'Authorization': `Bearer ${GH_TOKEN}`,
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (method === 'GET') return httpGet(targetUrl, headers);
  if (method === 'POST') return httpPost(targetUrl, body, headers);
  if (method === 'PATCH') {
    return new Promise((resolve, reject) => {
      const parsed = url.parse(targetUrl);
      const data = typeof body === 'string' ? body : JSON.stringify(body);
      const req = https.request({
        hostname: parsed.hostname,
        port: parsed.port || 443,
        path: parsed.path,
        method: 'PATCH',
        headers: {
          ...headers,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
        },
        timeout: 20000,
      }, res => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout`)); });
      req.write(data);
      req.end();
    });
  }
  throw new Error('Unsupported method: ' + method);
}

// ─── PR diff parsing ──────────────────────────────────────────────────────────
function readEvent() {
  if (!GH_EVENT || !fs.existsSync(GH_EVENT)) {
    return null;
  }
  return JSON.parse(fs.readFileSync(GH_EVENT, 'utf8'));
}

async function getPrChangedFiles(prNumber) {
  const files = [];
  let page = 1;
  while (true) {
    const res = await ghApi('GET', `/repos/${GH_REPO}/pulls/${prNumber}/files?per_page=100&page=${page}`);
    if (res.status !== 200) {
      console.error(`GitHub API error fetching PR files (${res.status}):`, res.body);
      break;
    }
    const batch = JSON.parse(res.body);
    if (batch.length === 0) break;
    files.push(...batch);
    if (batch.length < 100) break;
    page++;
  }
  return files;
}

// ─── Pattern scanning ─────────────────────────────────────────────────────────
async function scanFiles(files) {
  const findings = []; // { pattern, file, line }
  for (const file of files) {
    if (file.status === 'removed') continue;
    if (file.changes > 5000) {
      // skip massive vendored files; they often false-trigger on broad regexes
      continue;
    }
    const filename = file.filename || '';
    if (/\.(min\.)?(js|css)\b|node_modules\/|vendor\/|dist\/|build\//.test(filename)) continue;
    if (!/\.(py|js|jsx|ts|tsx|cjs|mjs|json|yaml|yml|md)$/.test(filename)) continue;

    // Read patch content (the diff hunk) — only flag matches in ADDED lines
    const patch = file.patch || '';
    const addedLines = patch.split('\n').filter(l => l.startsWith('+') && !l.startsWith('+++'));
    const addedText = addedLines.map(l => l.slice(1)).join('\n');
    if (!addedText) continue;

    for (const pattern of PATTERNS) {
      if (pattern.regex.test(addedText)) {
        // Find first matching line for the comment context
        const idx = addedLines.findIndex(l => pattern.regex.test(l));
        const sampleLine = idx >= 0 ? addedLines[idx].slice(1).trim().slice(0, 120) : '';
        findings.push({
          pattern_id: pattern.id,
          file: filename,
          sample_line: sampleLine,
          domains: pattern.domains,
          keywords: pattern.keywords,
          description: pattern.description,
        });
      }
    }
  }
  return findings;
}

// ─── Bidda registry lookup ────────────────────────────────────────────────────
async function fetchRelevantNodes(findings) {
  // Get the discovery index once (cached for the run)
  const indexUrl = `${API_URL}/nodes/index.json`;
  let index;
  try {
    const res = await httpGet(indexUrl);
    if (res.status !== 200) {
      console.error(`Bidda discovery API returned ${res.status}; skipping node lookup`);
      return new Map();
    }
    index = JSON.parse(res.body);
  } catch (err) {
    console.error('Bidda API fetch failed:', err.message);
    return new Map();
  }

  const arr = Array.isArray(index) ? index : (index.nodes || []);
  const matchesByPattern = new Map(); // pattern_id -> [{ node_id, title, domain, bluf }]
  const seenPatterns = new Set();

  for (const f of findings) {
    if (seenPatterns.has(f.pattern_id)) continue;
    seenPatterns.add(f.pattern_id);

    // Score nodes by domain match + keyword match in title/bluf
    const scored = [];
    for (const node of arr) {
      let score = 0;
      if (f.domains.includes(node.domain)) score += 3;
      const haystack = `${node.title || ''} ${node.bluf || ''}`.toLowerCase();
      for (const kw of f.keywords) {
        if (haystack.includes(kw.toLowerCase())) score += 2;
      }
      if (score > 0) scored.push({ ...node, _score: score });
    }
    scored.sort((a, b) => b._score - a._score);
    matchesByPattern.set(f.pattern_id, scored.slice(0, 3));
  }
  return matchesByPattern;
}

// ─── PR comment renderer ──────────────────────────────────────────────────────
function renderComment(findings, matchesByPattern) {
  const totalNodes = [...matchesByPattern.values()].reduce((acc, arr) => acc + arr.length, 0);
  if (findings.length === 0 || totalNodes === 0) {
    return null; // no comment if no findings
  }

  const lines = [];
  lines.push(COMMENT_MARKER);
  lines.push('');
  lines.push('## 🛡️ Bidda Agent Compliance Scanner');
  lines.push('');
  lines.push(`Detected ${findings.length} AI/agent code pattern(s) in this PR. Below are relevant compliance nodes from the [Bidda registry](https://bidda.com) — **advisory only**, not a legal opinion.`);
  lines.push('');

  // Group findings by pattern_id
  const byPattern = new Map();
  for (const f of findings) {
    if (!byPattern.has(f.pattern_id)) byPattern.set(f.pattern_id, { ...f, files: [] });
    byPattern.get(f.pattern_id).files.push(f.file);
  }

  let count = 0;
  for (const [pattern_id, info] of byPattern) {
    if (count >= MAX_NODES) break;
    const nodes = matchesByPattern.get(pattern_id) || [];
    if (nodes.length === 0) continue;

    lines.push(`### \`${pattern_id}\``);
    lines.push(`**Detected in:** ${[...new Set(info.files)].slice(0, 5).map(f => `\`${f}\``).join(', ')}${info.files.length > 5 ? ` (+${info.files.length - 5} more)` : ''}`);
    lines.push(`${info.description}`);
    lines.push('');
    lines.push('**Relevant compliance nodes:**');
    for (const node of nodes.slice(0, 3)) {
      const nodeUrl = `https://bidda.com/nodes/${node.node_id}`;
      const apiUrl  = `${API_URL}/nodes/${node.node_id}`;
      const vaultUrl = `${API_URL}/vault/nodes/${node.node_id}`;
      lines.push(`- [\`${node.node_id}\`](${nodeUrl}) — ${node.title || '(no title)'}`);
      const bluf = (node.bluf || '').replace(/\s+/g, ' ').trim();
      if (bluf) lines.push(`  > ${bluf.slice(0, 200)}${bluf.length > 200 ? '…' : ''}`);
      lines.push(`  - Free metadata: ${apiUrl}`);
      lines.push(`  - Full deterministic workflow ($0.01 unlock): ${vaultUrl}`);
      count++;
      if (count >= MAX_NODES) break;
    }
    lines.push('');
  }

  lines.push('---');
  lines.push(`<sub>🛡️ Bidda Agent Compliance Scanner v0.1 · [Configure](https://github.com/marketplace/actions/bidda-agent-compliance-scanner) · [Suppress this comment](https://bidda.com/docs/scanner#suppress) · 10,000+ cryptographically-signed regulatory nodes · Severity: \`${SEVERITY}\` · Fail-on: \`${FAIL_ON}\`</sub>`);
  return lines.join('\n');
}

// ─── PR comment management (idempotent: update if exists) ─────────────────────
async function findExistingComment(prNumber) {
  let page = 1;
  while (true) {
    const res = await ghApi('GET', `/repos/${GH_REPO}/issues/${prNumber}/comments?per_page=100&page=${page}`);
    if (res.status !== 200) return null;
    const batch = JSON.parse(res.body);
    if (batch.length === 0) return null;
    for (const c of batch) {
      if (c.body && c.body.includes(COMMENT_MARKER)) return c;
    }
    if (batch.length < 100) return null;
    page++;
  }
}

async function postOrUpdateComment(prNumber, body) {
  const existing = await findExistingComment(prNumber);
  if (existing) {
    return ghApi('PATCH', `/repos/${GH_REPO}/issues/comments/${existing.id}`, { body });
  }
  return ghApi('POST', `/repos/${GH_REPO}/issues/${prNumber}/comments`, { body });
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const event = readEvent();
  if (!event) {
    console.error('No event payload — running outside GitHub Actions? Exiting.');
    process.exit(0);
  }

  const prNumber = event.pull_request?.number || event.number;
  if (!prNumber) {
    console.log('Not a pull_request event — nothing to scan.');
    process.exit(0);
  }

  console.log(`Scanning PR #${prNumber} in ${GH_REPO}…`);

  const files = await getPrChangedFiles(prNumber);
  console.log(`PR has ${files.length} changed file(s).`);

  const findings = await scanFiles(files);
  console.log(`Detected ${findings.length} AI/agent pattern(s) in added lines.`);

  if (findings.length === 0) {
    console.log('No matches — PR is clean.');
    setOutput('agent-patterns-found', '0');
    setOutput('matched-nodes', '[]');
    process.exit(0);
  }

  const matchesByPattern = await fetchRelevantNodes(findings);
  const totalNodes = [...matchesByPattern.values()].reduce((acc, arr) => acc + arr.length, 0);
  const matchedNodeIds = [...matchesByPattern.values()].flat().map(n => n.node_id);

  const comment = renderComment(findings, matchesByPattern);
  if (comment) {
    const res = await postOrUpdateComment(prNumber, comment);
    if (res.status >= 200 && res.status < 300) {
      console.log('PR comment posted/updated.');
    } else {
      console.error(`Failed to post comment (${res.status}):`, res.body.slice(0, 500));
    }
  }

  setOutput('agent-patterns-found', String(findings.length));
  setOutput('matched-nodes', JSON.stringify(matchedNodeIds));

  // Exit code policy — advisory by default
  if (FAIL_ON === 'block' && SEVERITY === 'block') {
    process.exit(1);
  }
  if (FAIL_ON === 'warn' && (SEVERITY === 'warn' || SEVERITY === 'block')) {
    process.exit(1);
  }
  process.exit(0);
}

function setOutput(name, value) {
  const f = process.env.GITHUB_OUTPUT;
  if (f) {
    fs.appendFileSync(f, `${name}<<EOF\n${value}\nEOF\n`);
  }
}

main().catch(err => {
  console.error('Scanner error:', err.message);
  console.error(err.stack);
  process.exit(0); // never fail the PR on scanner internal errors
});
