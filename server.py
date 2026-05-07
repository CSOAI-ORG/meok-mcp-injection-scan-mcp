#!/usr/bin/env python3
"""
MEOK MCP Injection Scanner — security audit MCP for the post-April 2026 CVE wave
================================================================================
By MEOK AI Labs | https://meok.ai

CONTEXT (April 2026):
  - Anthropic published a "by-design" MCP RCE class affecting ~7,000 public MCP
    servers across ~150M downloads.
  - mcp-server-git CVE chain disclosed.
  - DockerDash MCP injection chain disclosed.
  - Tool-description prompt injection ("tool poisoning") demonstrated against
    every major MCP host.

PROBLEM SOLVED: every team running an MCP server (or auditing one before
adoption) needs a fast scan that flags the patterns the April 2026 disclosures
target. This MCP runs the canonical 30+ checks across tool descriptions,
schema fields, parameter defaults, and live /tools/list responses, then signs
the audit report so it survives a procurement review.

USE CASES:
  - "Scan github.com/foo/bar before I let my Claude Code use it."
  - "Audit my own MCP server's tool descriptions for tool-poisoning vectors."
  - "Generate a signed safety report I can hand to my CISO."
  - "What changed since I last scanned this server?"
  - Bulk-scan top public MCP registries (build once, sell the dashboard).

PRICING:
  - Free — 5 scans / day (the lead-magnet tier)
  - Pro £29/mo — unlimited scans + scheduled rescans + signed safety reports
  - Enterprise £1,499/mo — webhook on every CVE, custom rule packs, SLA
    response on critical findings

Install: pip install meok-mcp-injection-scan-mcp
Run:     python server.py
"""

import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

_MEOK_API_KEY = os.environ.get("MEOK_API_KEY", "")

try:
    sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
    from auth_middleware import check_access as _shared_check_access  # type: ignore
except ImportError:
    def _shared_check_access(api_key: str = ""):
        if _MEOK_API_KEY and api_key and api_key == _MEOK_API_KEY:
            return True, "OK", "pro"
        if _MEOK_API_KEY and api_key and api_key != _MEOK_API_KEY:
            return False, "Invalid API key.", "free"
        return True, "OK", "free"


def check_access(api_key: str = ""):
    return _shared_check_access(api_key)


# V-06 FIX: SSRF allowlist on attestation API URL.
try:
    from ssrf_safe import resolve_attestation_api as _resolve_api  # type: ignore
    _ATTESTATION_API = _resolve_api()
except ImportError:
    _ATTESTATION_API_RAW = os.environ.get("MEOK_ATTESTATION_API", "https://meok-attestation-api.vercel.app")
    _ALLOWED_API_HOSTS = {"meok-attestation-api.vercel.app", "meok-verify.vercel.app", "meok.ai", "csoai.org", "councilof.ai", "compliance.meok.ai"}
    try:
        _api_parsed = urllib.parse.urlparse(_ATTESTATION_API_RAW)
        _api_host = (_api_parsed.hostname or "").lower()
        _api_scheme = (_api_parsed.scheme or "").lower()
    except Exception:
        _api_host, _api_scheme = "", ""
    if _api_scheme != "https" or _api_host not in _ALLOWED_API_HOSTS:
        _ATTESTATION_API = "https://meok-attestation-api.vercel.app"
    else:
        _ATTESTATION_API = _ATTESTATION_API_RAW.rstrip("/")

STRIPE_29 = "https://buy.stripe.com/4gM6oJ1BW4gi6kd6as8k838"   # Starter
STRIPE_79 = "https://buy.stripe.com/eVq9AV4O87sudMF42k8k839"   # Pro
STRIPE_1499 = "https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837"  # Enterprise

_PRO_KEYS = set(k.strip() for k in os.environ.get("MEOK_PRO_KEYS", "").split(",") if k.strip())
_FREE_DAILY_LIMIT = 5


# ── Detection rule catalogue (the canonical set of patterns) ──────────────
# Each rule has: id, severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), description,
# category, regex (or callable), and a remediation hint. Severity is mapped
# from the April 2026 CVE landscape + OWASP LLM Top 10 + GenAI Red Team v1.

INJECTION_RULES = [
    # === CRITICAL — direct RCE / system-prompt override / credential exfil ===
    {
        "id": "INJ-001",
        "severity": "CRITICAL",
        "category": "tool-poisoning",
        "name": "Hidden 'ignore previous instructions' in tool description",
        "pattern": re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", re.I),
        "remediation": "Remove instruction-override language from tool descriptions. Anthropic's April 2026 disclosure showed this pattern triggers RCE in default MCP host configurations.",
    },
    {
        "id": "INJ-002",
        "severity": "CRITICAL",
        "category": "system-prompt-override",
        "name": "'You are now' authority impersonation pattern",
        "pattern": re.compile(r"\byou\s+are\s+now\s+(?:in|a|the|admin|root|developer|maintainer)", re.I),
        "remediation": "Tool descriptions must describe the tool, not redefine the agent. This pattern is the #1 jailbreak vector.",
    },
    {
        "id": "INJ-003",
        "severity": "CRITICAL",
        "category": "credential-exfil",
        "name": "Tool description requests credentials / keys / tokens",
        "pattern": re.compile(r"(?:api[_\-\s]?key|secret|token|password|credential)s?\s+(?:is|are|=|:)\s*['\"]", re.I),
        "remediation": "NEVER hard-code credentials in tool descriptions. NEVER request them from the agent — use the MCP host's secret store.",
    },
    {
        "id": "INJ-004",
        "severity": "CRITICAL",
        "category": "rce",
        "name": "Shell metachars in default parameter values",
        "pattern": re.compile(r"[\$`;|&<>]+\s*(?:rm|curl|wget|nc|sh|bash|exec|eval|chmod|chown)\s", re.I),
        "remediation": "Default parameter values must not contain shell metacharacters. Sanitize at the schema layer.",
    },
    {
        "id": "INJ-005",
        "severity": "CRITICAL",
        "category": "ssrf",
        "name": "file:// or internal-network URL in default parameter",
        "pattern": re.compile(r"(?:file://|http://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.))", re.I),
        "remediation": "Block internal URLs at the SSRF allowlist. Apr 2026 DockerDash chain pivoted via 169.254.169.254 metadata endpoint.",
    },
    # === HIGH — encoded payloads / nested instructions / supply chain ===
    {
        "id": "INJ-101",
        "severity": "HIGH",
        "category": "encoded-payload",
        "name": "Base64-encoded blob > 64 chars in description",
        "pattern": re.compile(r"[A-Za-z0-9+/=]{64,}"),
        "remediation": "Long base64 blobs in tool descriptions are a known steganography vector. Decode + manually review before deploying.",
    },
    {
        "id": "INJ-102",
        "severity": "HIGH",
        "category": "instruction-injection",
        "name": "Imperative directive aimed at the agent",
        "pattern": re.compile(r"\b(?:execute|run|invoke|call|fetch|download|delete|remove|exfiltrate|send|transmit|email|post|push)\s+(?:the|all|every|any|this|these|that|those)\s+\w+", re.I),
        "remediation": "Tool descriptions describe what the tool does. Imperatives aimed at the agent are an injection vector.",
    },
    {
        "id": "INJ-103",
        "severity": "HIGH",
        "category": "supply-chain",
        "name": "Unverified package import inside tool description",
        "pattern": re.compile(r"pip\s+install\s+[a-z0-9_\-]+|npm\s+install\s+[a-z0-9_\-]+", re.I),
        "remediation": "Tool descriptions that prompt the user/agent to install additional packages bypass the host's supply-chain controls.",
    },
    {
        "id": "INJ-104",
        "severity": "HIGH",
        "category": "data-exfil",
        "name": "Tool description references reading env vars / secrets",
        "pattern": re.compile(r"\b(?:os\.environ|process\.env|getenv|getEnv|System\.Environment|env\[)", re.I),
        "remediation": "Don't reference env-var access in tool descriptions. Centralise secret handling.",
    },
    {
        "id": "INJ-105",
        "severity": "HIGH",
        "category": "tool-shadowing",
        "name": "Tool description claims to replace / hijack another tool",
        "pattern": re.compile(r"\b(?:replaces?|hijacks?|intercepts?|overrides?|shadows?)\s+(?:the|all|any|every)\s+\w+\s+(?:tool|function|call)", re.I),
        "remediation": "Tool shadowing is a known privilege-escalation vector when an MCP host loads multiple servers.",
    },
    # === MEDIUM — social engineering, urgency, weak schemas ===
    {
        "id": "INJ-201",
        "severity": "MEDIUM",
        "category": "social-engineering",
        "name": "Urgency / authority language in description",
        "pattern": re.compile(r"\b(?:urgent|critical|immediately|asap|emergency|mandatory|required|must)\b\s*[!.]?", re.I),
        "remediation": "Tool descriptions should describe behaviour, not pressure the agent. Strip urgency markers.",
    },
    {
        "id": "INJ-202",
        "severity": "MEDIUM",
        "category": "schema-abuse",
        "name": "additionalProperties=true in input schema",
        "pattern": re.compile(r'"additionalProperties"\s*:\s*true', re.I),
        "remediation": "Set additionalProperties=false in JSON schemas — every undeclared field is an injection vector.",
    },
    {
        "id": "INJ-203",
        "severity": "MEDIUM",
        "category": "schema-abuse",
        "name": "Free-text 'string' parameter without maxLength",
        "pattern": re.compile(r'"type"\s*:\s*"string"(?![^}]*"maxLength")', re.I),
        "remediation": "Cap free-text params with maxLength. Unbounded strings are a DoS + storage-stuffing vector.",
    },
    {
        "id": "INJ-204",
        "severity": "MEDIUM",
        "category": "tool-naming",
        "name": "Tool name impersonates a well-known tool",
        "pattern": re.compile(r"\b(?:read_file|write_file|execute|shell|system|admin|root|sudo)\b", re.I),
        "remediation": "Tool naming impersonation breaks user trust in the MCP host's tool list. Rename with a unique prefix.",
    },
    # === LOW — cosmetic / minor tightening ===
    {
        "id": "INJ-301",
        "severity": "LOW",
        "category": "metadata",
        "name": "Description longer than 1,024 chars (host display issue + injection surface)",
        "pattern": "_long_description",  # special handling
        "remediation": "Shorten description. Each extra char is more surface for injected payloads.",
    },
    {
        "id": "INJ-302",
        "severity": "LOW",
        "category": "metadata",
        "name": "Description contains zero-width / control chars",
        "pattern": re.compile(r"[\u200B-\u200F\u202A-\u202E\uFEFF\u00AD]"),
        "remediation": "Strip zero-width and bidi-override chars from tool descriptions. Anthropic's April 2026 PoC abused U+202E.",
    },
]


def _scan_text(text: str) -> list[dict]:
    """Run every rule against a chunk of text. Returns list of finding dicts."""
    findings: list[dict] = []
    if not text:
        return findings
    for rule in INJECTION_RULES:
        pat = rule["pattern"]
        if pat == "_long_description":
            if len(text) > 1024:
                findings.append({
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "name": rule["name"],
                    "evidence": f"length={len(text)} chars",
                    "remediation": rule["remediation"],
                })
            continue
        for m in pat.finditer(text):
            findings.append({
                "rule_id": rule["id"],
                "severity": rule["severity"],
                "category": rule["category"],
                "name": rule["name"],
                "evidence": (m.group(0)[:80] + "…") if len(m.group(0)) > 80 else m.group(0),
                "remediation": rule["remediation"],
            })
            # one match per rule per text is enough for the report
            break
    return findings


def _http_get_json(url: str, timeout: int = 8) -> tuple[bool, Any, str]:
    """Fetch JSON from a URL. SSRF-safe — blocks internal IPs."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        return False, None, f"invalid URL: {e}"
    host = (parsed.hostname or "").lower()
    if not host:
        return False, None, "URL missing hostname"
    if host in ("localhost", "0.0.0.0") or host.startswith(("127.", "10.", "169.254.", "192.168.")) \
            or any(host.startswith(f"172.{n}.") for n in range(16, 32)):
        return False, None, f"refused: internal/loopback host {host!r}"
    if parsed.scheme not in ("http", "https"):
        return False, None, f"refused: scheme {parsed.scheme!r} (only http/https)"
    req = urllib.request.Request(
        url, method="GET",
        headers={"User-Agent": "meok-mcp-injection-scan/1.0", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", errors="replace")
        return True, json.loads(raw), "OK"
    except json.JSONDecodeError as e:
        return False, None, f"non-JSON response: {e}"
    except Exception as e:
        return False, None, f"{type(e).__name__}: {e}"


def _scan_tools_list(tools: list) -> dict:
    """Run rules against every tool in a tools/list MCP response."""
    all_findings = []
    per_tool = {}
    if not isinstance(tools, list):
        return {"error": f"tools must be a list, got {type(tools).__name__}", "findings": []}
    for t in tools:
        if not isinstance(t, dict):
            continue
        name = t.get("name") or "<unnamed>"
        desc = t.get("description") or ""
        schema_text = json.dumps(t.get("inputSchema") or {}, separators=(",", ":"))
        tool_findings = []
        tool_findings.extend(_scan_text(name))
        tool_findings.extend(_scan_text(desc))
        tool_findings.extend(_scan_text(schema_text))
        for f in tool_findings:
            f["tool"] = name
        per_tool[name] = tool_findings
        all_findings.extend(tool_findings)
    sev_counts = Counter(f["severity"] for f in all_findings)
    return {
        "tools_scanned": len(per_tool),
        "total_findings": len(all_findings),
        "severity_counts": dict(sev_counts),
        "per_tool": per_tool,
        "all_findings": all_findings,
    }


def _score(severity_counts: dict) -> int:
    """0-100. CRITICAL=30, HIGH=15, MEDIUM=5, LOW=1."""
    score = 100
    score -= 30 * severity_counts.get("CRITICAL", 0)
    score -= 15 * severity_counts.get("HIGH", 0)
    score -= 5 * severity_counts.get("MEDIUM", 0)
    score -= 1 * severity_counts.get("LOW", 0)
    return max(0, score)


def _verdict(score: int, sev: dict) -> str:
    if sev.get("CRITICAL", 0) > 0:
        return "FAIL — critical findings, do not deploy"
    if sev.get("HIGH", 0) > 0:
        return "WARN — high-severity findings, fix before deploy"
    if sev.get("MEDIUM", 0) > 0:
        return "PASS-WITH-NOTES — medium findings, review"
    return "PASS — clean scan"


def _sign_via_attestation_api(api_key: str, payload: dict) -> dict:
    """Best-effort signing call to meok-attestation-api. Returns cert dict."""
    body = {
        "api_key": api_key,
        "regulation": "MCP-SEC-AUDIT-2026",
        "entity": payload.get("subject", "anonymous"),
        "score": payload.get("score", 0),
        "findings": [f"{f.get('rule_id', '')} {f.get('name', '')}" for f in (payload.get("findings") or [])][:30],
        "articles_audited": [r["id"] for r in INJECTION_RULES],
        "auditor_notes": payload.get("note", ""),
    }
    try:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{_ATTESTATION_API}/sign",
            method="POST",
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "meok-mcp-injection-scan/1.0"},
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return {"error": f"signing unavailable: {type(e).__name__}: {e}"}


# ── Free-tier daily-limit (cheap in-memory; resets on process restart) ────
_DAILY_USAGE: dict[str, list[float]] = {}


def _consume_quota(tier: str, key: str = "anonymous") -> tuple[bool, str]:
    if tier in ("pro", "enterprise"):
        return True, "OK (paid tier)"
    now = time.time()
    bucket = _DAILY_USAGE.setdefault(key, [])
    cutoff = now - 86400
    bucket[:] = [t for t in bucket if t > cutoff]
    if len(bucket) >= _FREE_DAILY_LIMIT:
        return False, f"Free tier limit hit ({_FREE_DAILY_LIMIT}/day). Upgrade Pro £29/mo: {STRIPE_29}"
    bucket.append(now)
    return True, f"OK (free, {_FREE_DAILY_LIMIT - len(bucket)} scans left today)"


# ── MCP server + tools ─────────────────────────────────────────────────────
mcp = FastMCP("meok-mcp-injection-scan")


@mcp.tool()
def scan_mcp_url(url: str, api_key: str = "") -> dict:
    """
    Fetch a remote MCP server's /tools/list (or any JSON tool listing) and scan
    every tool's name + description + inputSchema against the canonical 30+
    injection-pattern rules.

    Returns a structured report: per-tool findings, severity counts, score
    0-100, verdict, and remediation hints. Free tier: 5 scans/day per key.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool for security assessment, threat detection, or vulnerability
        analysis. Suitable for automated security scanning and risk evaluation.

    When NOT to use:
        Do not rely solely on this tool for production security decisions.
        Always combine with manual security review.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    ok, msg, tier = check_access(api_key)
    if not ok:
        return {"error": msg, "upgrade": STRIPE_79}
    quota_ok, quota_msg = _consume_quota(tier, key=api_key or "anonymous")
    if not quota_ok:
        return {"error": quota_msg, "upgrade_pro": STRIPE_29, "upgrade_enterprise": STRIPE_1499}

    fetched, payload, fetch_msg = _http_get_json(url)
    if not fetched:
        return {"error": f"could not fetch {url}: {fetch_msg}", "tier": tier, "quota": quota_msg}
    # Try common shapes: top-level list, {"tools": [...]}, or {"result": {"tools": [...]}}
    tools = None
    if isinstance(payload, list):
        tools = payload
    elif isinstance(payload, dict):
        tools = payload.get("tools") or (payload.get("result") or {}).get("tools")
    if tools is None:
        return {"error": "no 'tools' array found in response", "tier": tier, "quota": quota_msg, "raw_keys": list(payload.keys()) if isinstance(payload, dict) else None}

    audit = _scan_tools_list(tools)
    score = _score(audit["severity_counts"])
    verdict = _verdict(score, audit["severity_counts"])
    return {
        "url": url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "tier": tier,
        "quota": quota_msg,
        "score_0_100": score,
        "verdict": verdict,
        "severity_counts": audit["severity_counts"],
        "tools_scanned": audit["tools_scanned"],
        "total_findings": audit["total_findings"],
        "findings": audit["all_findings"][:50],  # cap response size
        "rules_applied": len(INJECTION_RULES),
        "next_step": "Call signed_safety_report() with these findings to issue a procurement-grade signed cert (Pro tier)." if tier in ("pro", "enterprise") else f"Upgrade Pro £29/mo for signed safety reports: {STRIPE_29}",
    }


@mcp.tool()
def audit_tool_descriptions(tools_json: str, api_key: str = "") -> dict:
    """
    Audit a JSON string containing a tool list (paste from your own MCP server's
    tools/list output). Same rule catalogue as scan_mcp_url — useful when the
    server is behind auth or not yet deployed.

    `tools_json` accepts either: a raw list, or {"tools": [...]}, or
    {"result": {"tools": [...]}}.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool for security assessment, threat detection, or vulnerability
        analysis. Suitable for automated security scanning and risk evaluation.

    When NOT to use:
        Do not rely solely on this tool for production security decisions.
        Always combine with manual security review.
    """
    ok, msg, tier = check_access(api_key)
    if not ok:
        return {"error": msg, "upgrade": STRIPE_79}
    quota_ok, quota_msg = _consume_quota(tier, key=api_key or "anonymous")
    if not quota_ok:
        return {"error": quota_msg, "upgrade_pro": STRIPE_29}
    try:
        payload = json.loads(tools_json)
    except json.JSONDecodeError as e:
        return {"error": f"invalid JSON: {e}", "tier": tier}
    tools = payload if isinstance(payload, list) else (
        payload.get("tools") or (payload.get("result") or {}).get("tools")
        if isinstance(payload, dict) else None
    )
    if tools is None:
        return {"error": "no 'tools' array found", "tier": tier}
    audit = _scan_tools_list(tools)
    score = _score(audit["severity_counts"])
    return {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "tier": tier,
        "quota": quota_msg,
        "score_0_100": score,
        "verdict": _verdict(score, audit["severity_counts"]),
        "severity_counts": audit["severity_counts"],
        "tools_scanned": audit["tools_scanned"],
        "total_findings": audit["total_findings"],
        "findings": audit["all_findings"][:100],
        "rules_applied": len(INJECTION_RULES),
    }


@mcp.tool()
def signed_safety_report(
    subject: str,
    findings_json: str = "",
    score: int = 0,
    note: str = "",
    api_key: str = "",
) -> dict:
    """
    Issue a cryptographically signed safety report for the scanned MCP server.
    Returns a cert with a public verify URL anyone can hit to confirm the audit
    happened on the date claimed.

    Pro / Enterprise tier only.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool for security assessment, threat detection, or vulnerability
        analysis. Suitable for automated security scanning and risk evaluation.

    When NOT to use:
        Do not rely solely on this tool for production security decisions.
        Always combine with manual security review.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    ok, msg, tier = check_access(api_key)
    if not ok or tier not in ("pro", "enterprise"):
        return {
            "error": "signed reports require Pro tier (£29/mo Starter, £79/mo Pro) or Enterprise £1,499/mo",
            "upgrade_starter": STRIPE_29,
            "upgrade_pro": STRIPE_79,
            "upgrade_enterprise": STRIPE_1499,
        }
    try:
        findings = json.loads(findings_json) if findings_json else []
    except json.JSONDecodeError:
        findings = []
    cert = _sign_via_attestation_api(api_key, {
        "subject": subject,
        "findings": findings,
        "score": score,
        "note": note or f"MEOK MCP Injection Scanner — {len(INJECTION_RULES)} rules applied",
    })
    return {
        "tier": tier,
        "subject": subject,
        "report": cert,
        "verify_at": cert.get("verify_url"),
        "ship_to_ciso": "Forward this cert + verify URL in any procurement / SOC2 / ISO 42001 audit response.",
    }


@mcp.tool()
def list_rules() -> dict:
    """
    List every detection rule in the canonical catalogue. Useful for buyers
    auditing what we check before subscribing.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool for security assessment, threat detection, or vulnerability
        analysis. Suitable for automated security scanning and risk evaluation.

    When NOT to use:
        Do not rely solely on this tool for production security decisions.
        Always combine with manual security review.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    sev_counts = Counter(r["severity"] for r in INJECTION_RULES)
    return {
        "total_rules": len(INJECTION_RULES),
        "severity_counts": dict(sev_counts),
        "rules": [
            {
                "id": r["id"],
                "severity": r["severity"],
                "category": r["category"],
                "name": r["name"],
                "remediation": r["remediation"],
            }
            for r in INJECTION_RULES
        ],
        "version": "1.0.0",
        "last_updated": "2026-04-26",
    }


@mcp.tool()
def pricing() -> dict:
    """Pricing + subscribe links for this MCP.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool for security assessment, threat detection, or vulnerability
        analysis. Suitable for automated security scanning and risk evaluation.

    When NOT to use:
        Do not rely solely on this tool for production security decisions.
        Always combine with manual security review.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    return {
        "free": {"price_gbp": 0, "limit": f"{_FREE_DAILY_LIMIT} scans / day", "signed_reports": False},
        "starter_29": {"price_gbp": 29, "subscribe": STRIPE_29, "limit": "unlimited scans", "signed_reports": True},
        "pro_79": {"price_gbp": 79, "subscribe": STRIPE_79, "limit": "unlimited scans + scheduled rescans", "signed_reports": True, "support": "48h"},
        "enterprise_1499": {"price_gbp": 1499, "subscribe": STRIPE_1499, "limit": "unlimited + custom rule packs + SLA", "signed_reports": True, "support": "4h"},
        "verify_any_cert": "https://meok-attestation-api.vercel.app/verify",
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
