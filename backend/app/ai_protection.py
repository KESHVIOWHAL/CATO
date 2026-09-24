"""
CATO — AI Interaction Protection Layer
=======================================
Corresponds to the left panel of the CATO architecture:
  Developer Input → AI Interaction Protection → ACTION: DETECT → SANITIZE → BLOCK → ROUTE

Checks performed on developer-provided input (prompts, source code, context, requirements):
  1. Secret & Credential Detection  — raw secrets in prompts or pasted code
  2. Sensitive Context Detection    — PII, internal URLs, confidential markers
  3. Prompt / Agent Risk Analysis   — prompt injection patterns, jailbreak attempts
  4. Policy Evaluation              — does the input violate org policy?
"""

import re
from typing import List
from models import Severity


# ── Data models ───────────────────────────────────────────────────────────────

class ProtectionFinding:
    def __init__(self, category: str, severity: Severity, title: str,
                 description: str, action: str, line: int = 0):
        self.category    = category
        self.severity    = severity
        self.title       = title
        self.description = description
        self.action      = action   # BLOCK | SANITIZE | WARN
        self.line        = line

    def to_dict(self) -> dict:
        return {
            "category":    self.category,
            "severity":    self.severity,
            "title":       self.title,
            "description": self.description,
            "action":      self.action,
            "line":        self.line,
        }


class ProtectionResult:
    def __init__(self):
        self.findings: List[ProtectionFinding] = []
        self.blocked        = False
        self.sanitized_text = ""
        self.routing        = "APPROVED_EXT_AI"   # LOCAL_AI | ENTERPRISE_AI | APPROVED_EXT_AI
        self.summary        = ""

    def to_dict(self) -> dict:
        return {
            "findings":       [f.to_dict() for f in self.findings],
            "blocked":        self.blocked,
            "routing":        self.routing,
            "summary":        self.summary,
        }


# ── Detection rules ───────────────────────────────────────────────────────────

_SECRET_PATTERNS = [
    ("API Key in prompt",       re.compile(r'(?:api_key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9\-_]{16,})', re.I),  "BLOCK"),
    ("Password in prompt",      re.compile(r'(?:password|passwd)\s*[:=]\s*["\']?(\S{6,})',              re.I),  "BLOCK"),
    ("AWS key in prompt",       re.compile(r'AKIA[0-9A-Z]{16}'),                                                "BLOCK"),
    ("GitHub token in prompt",  re.compile(r'ghp_[A-Za-z0-9]{36}'),                                            "BLOCK"),
    ("Private key in prompt",   re.compile(r'-----BEGIN.*PRIVATE KEY-----'),                                    "BLOCK"),
]

_SENSITIVE_CONTEXT_PATTERNS = [
    ("Internal IP / hostname",  re.compile(r'\b10\.\d+\.\d+\.\d+|\b192\.168\.\d+\.\d+|\blocalhost\b', re.I),   "WARN"),
    ("PII — email address",     re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b'),                "SANITIZE"),
    ("PII — phone number",      re.compile(r'\b(?:\+91|0)?[6-9]\d{9}\b|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b'),     "SANITIZE"),
    ("Confidential marker",     re.compile(r'\b(?:CONFIDENTIAL|TOP SECRET|INTERNAL ONLY|DO NOT SHARE)\b', re.I),"WARN"),
    ("Database connection str", re.compile(r'(?:mongodb|postgresql|mysql|redis)://\S+', re.I),                   "BLOCK"),
]

_PROMPT_INJECTION_PATTERNS = [
    ("Prompt injection — ignore instructions",
     re.compile(r'ignore\s+(all\s+)?(?:previous|above|prior)\s+instructions?', re.I), "BLOCK"),
    ("Prompt injection — jailbreak DAN",
     re.compile(r'\bDAN\b|\bdo anything now\b', re.I), "BLOCK"),
    ("Prompt injection — role override",
     re.compile(r'you\s+are\s+now\s+(?:a\s+)?(?:hacker|attacker|evil|malicious)', re.I), "BLOCK"),
    ("Prompt injection — system override",
     re.compile(r'<\s*(?:system|SYSTEM)\s*>|(?:system\s+prompt\s*:)', re.I), "WARN"),
    ("Agent risk — exfiltration attempt",
     re.compile(r'send\s+(?:all\s+)?(?:data|files|credentials|secrets)\s+to', re.I), "BLOCK"),
]


def analyze_input(text: str, policy: dict = {}) -> ProtectionResult:
    """
    Analyze developer input text (prompt / source code / context) for risks.
    Returns a ProtectionResult with findings, routing decision, and sanitized text.
    """
    result = ProtectionResult()
    sanitized = text
    lines = text.splitlines()

    def check_patterns(patterns, category):
        nonlocal sanitized
        for title, pattern, default_action in patterns:
            for lineno, line in enumerate(lines, start=1):
                m = pattern.search(line)
                if m:
                    action = default_action
                    result.findings.append(ProtectionFinding(
                        category=category,
                        severity=Severity.CRITICAL if action == "BLOCK" else Severity.HIGH if action == "SANITIZE" else Severity.MEDIUM,
                        title=title,
                        description=f"Detected at line {lineno}: {line.strip()[:80]}",
                        action=action,
                        line=lineno,
                    ))
                    if action in ("BLOCK", "SANITIZE"):
                        sanitized = pattern.sub("[REDACTED]", sanitized)

    check_patterns(_SECRET_PATTERNS,             "SECRET_CREDENTIAL")
    check_patterns(_SENSITIVE_CONTEXT_PATTERNS,  "SENSITIVE_CONTEXT")
    check_patterns(_PROMPT_INJECTION_PATTERNS,   "PROMPT_INJECTION")

    # Determine outcome
    has_block = any(f.action == "BLOCK" for f in result.findings)
    has_sensitive = any(f.category == "SENSITIVE_CONTEXT" for f in result.findings)

    result.blocked = has_block
    result.sanitized_text = sanitized

    # Routing decision based on risk level
    if has_block:
        result.routing = "BLOCKED"
    elif has_sensitive:
        result.routing = "LOCAL_AI"          # sensitive context → use local model only
    elif result.findings:
        result.routing = "ENTERPRISE_AI"     # some risk → use controlled enterprise model
    else:
        result.routing = "APPROVED_EXT_AI"  # clean → any approved external AI

    total = len(result.findings)
    if total == 0:
        result.summary = "No risks detected — input cleared for AI processing"
    elif has_block:
        result.summary = f"{total} issue(s) detected — INPUT BLOCKED before AI routing"
    else:
        result.summary = f"{total} issue(s) detected — input sanitized and routed to {result.routing}"

    return result
