[![meok-mcp-injection-scan-mcp MCP server](https://glama.ai/mcp/servers/CSOAI-ORG/meok-mcp-injection-scan-mcp/badges/card.svg)](https://glama.ai/mcp/servers/CSOAI-ORG/meok-mcp-injection-scan-mcp)

# meok-mcp-injection-scan-mcp

[![PyPI version](https://img.shields.io/pypi/v/meok-mcp-injection-scan-mcp)](https://pypi.org/project/meok-mcp-injection-scan-mcp/)
[![PyPI downloads](https://img.shields.io/pypi/dw/meok-mcp-injection-scan-mcp)](https://pypistats.org/packages/meok-mcp-injection-scan-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-255+_servers-purple)](https://meok.ai)

**Scan any MCP server for the prompt-injection / tool-poisoning / SSRF class disclosed in the April 2026 CVE wave.**

```
pip install meok-mcp-injection-scan-mcp
```

## Why this exists

April 2026 was a bad month for MCP. Anthropic published a "by-design" MCP RCE class affecting ~7,000 public servers (~150M downloads). `mcp-server-git` shipped a CVE chain. DockerDash got popped by an injection chain. Tool-description prompt injection ("tool poisoning") was demonstrated against every major MCP host.

If you run an MCP server in production, or you're auditing one before adoption, you need a fast scan that flags the patterns the April 2026 disclosures target. This MCP is that scan.

## What it checks

**30+ canonical rules** across 5 severity tiers:

- **CRITICAL** — direct RCE, system-prompt override, credential exfil patterns, shell metachars in defaults, file:// / internal-network URLs (the DockerDash 169.254.169.254 metadata-pivot vector).
- **HIGH** — encoded payloads, imperative directives at the agent, supply-chain prompts, env-var references, tool shadowing.
- **MEDIUM** — urgency / authority language, `additionalProperties=true`, unbounded strings, tool-name impersonation.
- **LOW** — over-long descriptions, zero-width / bidi-override chars (the U+202E PoC vector).

Coverage maps to: OWASP LLM Top 10, GenAI Red Team v1, the April 2026 Anthropic MCP RCE disclosure, and the `mcp-server-git` CVE chain.

## Tools exposed

| Tool | Purpose |
|---|---|
| `scan_mcp_url(url)` | Fetch a remote MCP server's tool listing and scan it |
| `audit_tool_descriptions(tools_json)` | Scan a pasted JSON tool list (auth-walled servers) |
| `signed_safety_report(subject, findings_json, score, note)` | Issue a procurement-grade signed cert (Pro tier) |
| `list_rules()` | Inspect the full rule catalogue before subscribing |
| `pricing()` | Subscribe links + tier comparison |

## Pricing

| Tier | Price | What you get |
|---|---|---|
| Free | £0 | 5 scans / day, no signed reports |
| Starter | [£29/mo](https://buy.stripe.com/4gM6oJ1BW4gi6kd6as8k838) | Unlimited scans + signed reports |
| Pro | [£79/mo](https://buy.stripe.com/eVq9AV4O87sudMF42k8k839) | + scheduled rescans + 48h support |
| Enterprise | [£1,499/mo](https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837) | + custom rule packs + 4h SLA |

Every signed cert lives at `https://meok-attestation-api.vercel.app/verify/<cert_id>` — auditors and procurement teams confirm without an account.

## What you do NOT get

This is a static-pattern scanner. It does not run dynamic taint analysis, fuzz the server with adversarial inputs, or replace a human red-team. It is the first 80% of the audit, in 5 seconds, for free.

## Built by MEOK AI Labs

Solo founder. London. 234 MCP packages on PyPI. Live signing infrastructure at `meok-attestation-api.vercel.app`. Storefront `councilof.ai`. Get the catalogue: `https://meok-attestation-api.vercel.app/catalogue`.

---

## Distribution channels

- **PyPI**: `pip install meok-mcp-injection-scan-mcp` (this package)
- **Apify Store** (Pay-Per-Event): https://apify.com/knowing_yucca/meok-mcp-injection-scan
- **GitHub** (source): https://github.com/CSOAI-ORG/MEOK-LABS/tree/main/mcps/meok-mcp-injection-scan-mcp
- **Sponsor**: https://github.com/sponsors/CSOAI-ORG · [Pro £79/mo →](https://buy.stripe.com/eVq9AV4O87sudMF42k8k839)
<!-- mcp-name: io.github.CSOAI-ORG/meok-mcp-injection-scan-mcp -->
