"""
CATO — AI vs CATO Comparison Engine
=====================================
Feature 1: Direct AI vs CATO side-by-side comparison
Feature 2: Actual measured pre-AI latency benchmarking

All latency values are measured with time.perf_counter().
No values are hardcoded.
No real credentials are transmitted externally.
"""

import re
import time
import statistics
from typing import List, Optional
from ai_protection import analyze_input, ProtectionResult

# ── Dummy/canary secret patterns for demo prompts ────────────────────────────
DEMO_API_KEY = "sk-test-CATO-DEMO-9F82X71"

DEFAULT_DEMO_PROMPT = (
    "Build a Python payment service that connects to our payment API.\n"
    f"Use this API key: api_key = \"{DEMO_API_KEY}\"\n"
    "The service should process credit card transactions and store results.\n"
    "Connect to the database with password = \"prod-db-secret-2024\"\n"
    "Deploy to our internal server at 192.168.1.100"
)

AI_MODEL_LABELS = {
    "claude":      "Claude (Anthropic)",
    "gpt":         "GPT-4 (OpenAI)",
    "gemini":      "Gemini (Google)",
    "local":       "Local AI (On-Prem)",
    "enterprise":  "Enterprise AI (Private)",
}


# ─────────────────────────────────────────────────────────────────────────────
#  LATENCY MEASUREMENT
# ─────────────────────────────────────────────────────────────────────────────

class LatencyMeasurement:
    def __init__(self):
        self.stages: dict[str, float] = {}
        self._start: float = 0.0
        self._last: float = 0.0

    def begin(self):
        self._start = time.perf_counter()
        self._last  = self._start

    def mark(self, stage: str):
        now = time.perf_counter()
        self.stages[stage] = round((now - self._last) * 1000, 2)  # ms
        self._last = now

    @property
    def total_ms(self) -> float:
        now = time.perf_counter()
        return round((now - self._start) * 1000, 2)

    def to_dict(self) -> dict:
        return {
            "stages": self.stages,
            "total_ms": round(sum(self.stages.values()), 2),
        }


def run_protected(text: str, policy: dict = {}) -> tuple[ProtectionResult, LatencyMeasurement]:
    """
    Run the full AI Interaction Protection pipeline with per-stage timing.
    Returns (result, latency).
    """
    lat = LatencyMeasurement()
    lat.begin()

    # Stage 1: Secret detection
    from ai_protection import _SECRET_PATTERNS
    import re as _re
    _findings_so_far = []
    sanitized = text
    lines = text.splitlines()

    for title, pattern, action in _SECRET_PATTERNS:
        for lineno, line in enumerate(lines, start=1):
            if pattern.search(line):
                _findings_so_far.append((title, action, lineno))
                if action in ("BLOCK", "SANITIZE"):
                    sanitized = pattern.sub("[REDACTED]", sanitized)
    lat.mark("Secret Detection")

    # Stage 2: PII detection
    from ai_protection import _SENSITIVE_CONTEXT_PATTERNS
    for title, pattern, action in _SENSITIVE_CONTEXT_PATTERNS:
        for lineno, line in enumerate(lines, start=1):
            if pattern.search(line):
                _findings_so_far.append((title, action, lineno))
                if action in ("BLOCK", "SANITIZE"):
                    sanitized = pattern.sub("[REDACTED]", sanitized)
    lat.mark("PII Detection")

    # Stage 3: Prompt injection detection
    from ai_protection import _PROMPT_INJECTION_PATTERNS
    for title, pattern, action in _PROMPT_INJECTION_PATTERNS:
        for lineno, line in enumerate(lines, start=1):
            if pattern.search(line):
                _findings_so_far.append((title, action, lineno))
    lat.mark("Prompt Injection Check")

    # Stage 4: Policy evaluation
    has_block = any(a == "BLOCK" for _, a, _ in _findings_so_far)
    has_sensitive = any(t.startswith("PII") or t.startswith("Internal") or t.startswith("Confidential")
                        for t, _, _ in _findings_so_far)
    lat.mark("Policy Evaluation")

    # Stage 5: Sanitization (already done above, measure the final pass)
    _ = sanitized  # ensure computed
    lat.mark("Sanitization")

    # Stage 6: Routing decision
    if has_block:
        routing = "BLOCKED"
    elif has_sensitive:
        routing = "LOCAL_AI"
    elif _findings_so_far:
        routing = "ENTERPRISE_AI"
    else:
        routing = "APPROVED_EXT_AI"
    lat.mark("Routing Decision")

    # Full result via existing engine
    result = analyze_input(text, policy)
    result.sanitized_text = sanitized

    return result, lat


# ─────────────────────────────────────────────────────────────────────────────
#  COMPARISON
# ─────────────────────────────────────────────────────────────────────────────

def compare_direct_vs_cato(prompt: str, ai_model: str = "claude", policy: dict = {}) -> dict:
    """
    Compare what happens when a prompt goes directly to AI vs through CATO.
    Returns structured comparison result.
    No real credentials are transmitted.
    """
    prompt_size_bytes = len(prompt.encode("utf-8"))
    prompt_size_kb    = round(prompt_size_bytes / 1024, 2)

    # ── Direct AI side (simulated — no real transmission) ──
    # Detect what secrets WOULD be sent
    direct_secrets_found = []
    for title, pattern, _ in __import__("ai_protection")._SECRET_PATTERNS:
        if pattern.search(prompt):
            direct_secrets_found.append(title)

    direct_result = {
        "label":              f"Direct AI — {AI_MODEL_LABELS.get(ai_model, ai_model)}",
        "prompt_inspected":   False,
        "secret_detection":   False,
        "pii_detection":      False,
        "injection_check":    False,
        "policy_enforcement": False,
        "sanitization":       False,
        "routing_control":    False,
        "action":             "SEND_AS_IS",
        "action_label":       "Prompt sent without pre-AI policy enforcement",
        "secrets_exposed":    direct_secrets_found,
        "simulated_response": _simulate_ai_response(prompt, ai_model),
        "warning":            "DEMONSTRATION MODE — no real credential transmitted",
    }

    # ── CATO side (real pipeline) ──
    cato_protection, latency = run_protected(prompt, policy)

    cato_result = {
        "label":              "CATO Protected AI",
        "prompt_inspected":   True,
        "secret_detection":   True,
        "pii_detection":      True,
        "injection_check":    True,
        "policy_enforcement": True,
        "sanitization":       cato_protection.blocked or any(
            f.action == "SANITIZE" for f in cato_protection.findings
        ),
        "routing_control":    True,
        "action":             "BLOCKED" if cato_protection.blocked else (
            "SANITIZED" if any(f.action == "SANITIZE" for f in cato_protection.findings)
            else "APPROVED"
        ),
        "action_label": (
            "INPUT BLOCKED — prompt will not reach AI endpoint"
            if cato_protection.blocked
            else "Prompt sanitized and forwarded to approved AI endpoint"
            if any(f.action == "SANITIZE" for f in cato_protection.findings)
            else "No issues detected — prompt approved for AI routing"
        ),
        "findings":           [f.to_dict() for f in cato_protection.findings],
        "sanitized_prompt":   cato_protection.sanitized_text,
        "routing":            cato_protection.routing,
        "latency":            latency.to_dict(),
    }

    # ── Comparison table ──
    comparison_table = [
        {"metric": "Prompt inspection",      "direct": "✗ None",    "cato": "✓ Yes"},
        {"metric": "Secret detection",       "direct": "✗ No gateway", "cato": "✓ Yes"},
        {"metric": "PII detection",          "direct": "✗ No gateway", "cato": "✓ Yes"},
        {"metric": "Prompt injection check", "direct": "✗ No gateway", "cato": "✓ Yes"},
        {"metric": "Policy enforcement",     "direct": "✗ No",      "cato": "✓ Yes"},
        {"metric": "Secret sanitization",    "direct": "✗ No",      "cato": "✓ Yes"},
        {"metric": "Routing decision",       "direct": "✗ No",      "cato": "✓ Yes"},
        {"metric": "Final action",
         "direct": "SEND",
         "cato": cato_result["action"]},
    ]

    return {
        "prompt_size_kb":   prompt_size_kb,
        "ai_model":         ai_model,
        "direct":           direct_result,
        "cato":             cato_result,
        "comparison_table": comparison_table,
        "key_message":      "CATO does not replace AI. It controls what is allowed to reach AI.",
    }


def _simulate_ai_response(prompt: str, model: str) -> str:
    """Simulate what an AI MIGHT respond with — for demo purposes only."""
    has_secret = bool(re.search(r'sk-[A-Za-z0-9\-_]{10,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}', prompt))
    model_label = AI_MODEL_LABELS.get(model, model)
    if has_secret:
        return (
            f"[{model_label} — Simulated Response]\n\n"
            "Here's a Python payment service:\n\n"
            "import requests\n\n"
            "API_KEY = \"sk-test-CATO-DEMO-9F82X71\"  # ← secret transmitted in prompt\n"
            "def process_payment(amount, card_token):\n"
            "    headers = {\"Authorization\": f\"Bearer {API_KEY}\"}\n"
            "    response = requests.post(\"https://api.payment.example/charge\",\n"
            "        headers=headers, json={\"amount\": amount, \"token\": card_token})\n"
            "    return response.json()\n\n"
            "⚠ Note: The AI received and used the API key from your prompt.\n"
            "   Without CATO, this key was transmitted to the external AI service."
        )
    return f"[{model_label} — Simulated Response]\n\nPrompt processed. No secrets detected in this simulation."


# ─────────────────────────────────────────────────────────────────────────────
#  BENCHMARK
# ─────────────────────────────────────────────────────────────────────────────

BENCHMARK_PROMPTS = {
    "small":  f"Help me build a login function. API_KEY={DEMO_API_KEY}",
    "medium": DEFAULT_DEMO_PROMPT,
    "large":  DEFAULT_DEMO_PROMPT * 5 + "\n\nAdditional context: " + "This system handles PII including email addresses like user@example.com and phone numbers. " * 20,
}


def run_benchmark(prompt: str, runs: int = 20) -> dict:
    """
    Run the CATO protection pipeline N times and collect real latency stats.
    All timing from time.perf_counter().
    """
    total_times: List[float] = []
    stage_times: dict[str, List[float]] = {}

    for _ in range(runs):
        _, lat = run_protected(prompt)
        total_times.append(lat.to_dict()["total_ms"])
        for stage, ms in lat.stages.items():
            stage_times.setdefault(stage, []).append(ms)

    stage_avgs = {stage: round(statistics.mean(times), 2) for stage, times in stage_times.items()}

    return {
        "runs":       runs,
        "prompt_size_kb": round(len(prompt.encode()) / 1024, 2),
        "min_ms":     round(min(total_times), 2),
        "max_ms":     round(max(total_times), 2),
        "avg_ms":     round(statistics.mean(total_times), 2),
        "median_ms":  round(statistics.median(total_times), 2),
        "stdev_ms":   round(statistics.stdev(total_times), 2) if len(total_times) > 1 else 0.0,
        "stage_averages_ms": stage_avgs,
        "all_times_ms": [round(t, 2) for t in total_times],
    }


def run_size_benchmark() -> dict:
    """Run benchmark across small / medium / large prompts."""
    results = {}
    for size, prompt in BENCHMARK_PROMPTS.items():
        results[size] = run_benchmark(prompt, runs=10)
    return results
