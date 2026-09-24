from typing import List, Tuple, Dict, Any
from models import CheckResult, CheckStatus, Decision, Severity, PolicyResult, Recommendation

DEFAULT_POLICY = {
    "critical_secret": "BLOCK",
    "high_vulnerability": "BLOCK",
    "medium_vulnerability": "REVIEW",
    "failed_tests": "REVIEW",
}

# Severity penalty weights for trust score
SEVERITY_PENALTY = {
    Severity.CRITICAL: 30,
    Severity.HIGH:     15,
    Severity.MEDIUM:   7,
    Severity.LOW:      2,
}


def make_decision(
    checks: List[CheckResult],
    policy_config: Dict[str, Any] = {},
) -> Tuple[Decision, str, int, List[str], PolicyResult, List[Recommendation]]:
    policy = {**DEFAULT_POLICY, **policy_config}
    reasons: List[str] = []
    recommendations: List[Recommendation] = []

    has_critical = has_high = has_medium = False
    tests_passed = tests_ran = False
    trust_score = 100
    priority_counter = 1

    for check in checks:
        if check.check_name == "Functional Tests":
            tests_ran = True
            if check.status == CheckStatus.FAIL:
                tests_passed = False
                reasons.append(f"Functional tests FAILED — {check.summary}")
                trust_score -= 20
                recommendations.append(Recommendation(
                    priority=priority_counter,
                    category="TEST",
                    title="Fix failing tests",
                    what="Functional tests failed. Deploying untested code increases the risk of runtime failures.",
                    fix="Run pytest locally, examine the failure output, and fix the failing test cases or the code they cover.",
                    severity=Severity.HIGH,
                ))
                priority_counter += 1
            else:
                tests_passed = True
            continue

        # Deduplicate recommendations by title
        rec_titles_seen = set()

        for finding in check.findings:
            loc = f" at {finding.location}" if finding.location else ""
            penalty = SEVERITY_PENALTY.get(finding.severity, 5)
            trust_score = max(0, trust_score - penalty)

            if finding.severity == Severity.CRITICAL:
                has_critical = True
                reasons.append(f"[CRITICAL] {finding.title}{loc} — {check.check_name}")
            elif finding.severity == Severity.HIGH:
                has_high = True
                reasons.append(f"[HIGH] {finding.title}{loc} — {check.check_name}")
            elif finding.severity == Severity.MEDIUM:
                has_medium = True
                reasons.append(f"[MEDIUM] {finding.title}{loc} — {check.check_name}")

            # Build recommendation (deduplicated by title so we don't repeat same CVE fix 3x)
            rec_key = f"{finding.title}:{check.check_name}"
            if rec_key not in rec_titles_seen and finding.remediation:
                rec_titles_seen.add(rec_key)
                category = (
                    "SECRET"     if "secret" in check.check_name.lower() or "secret" in finding.title.lower()
                    else "SAST"       if "sast" in check.check_name.lower() or "static" in check.check_name.lower()
                    else "DEPENDENCY" if "depend" in check.check_name.lower()
                    else "POLICY"
                )
                recommendations.append(Recommendation(
                    priority=priority_counter,
                    category=category,
                    title=finding.title,
                    what=finding.description,
                    fix=finding.remediation,
                    severity=finding.severity,
                    location=finding.location,
                ))
                priority_counter += 1

    # Add general dependency upgrade rec if many vulns found
    dep_check = next((c for c in checks if "depend" in c.check_name.lower()), None)
    if dep_check and dep_check.findings:
        unique_pkgs = {f.location.split("(")[1].split("==")[0] for f in dep_check.findings if f.location and "(" in f.location}
        if unique_pkgs:
            recommendations.append(Recommendation(
                priority=priority_counter,
                category="DEPENDENCY",
                title="Pin dependencies to patched versions",
                what=f"{len(dep_check.findings)} vulnerability(s) found across {len(unique_pkgs)} package(s).",
                fix=(
                    "Run: pip list --outdated  to see all outdated packages.\n"
                    "Run: pip install --upgrade " + " ".join(unique_pkgs) + "\n"
                    "Then pin exact versions in requirements.txt using: pip freeze > requirements.txt\n"
                    "Consider using 'pip-audit' or 'safety' for ongoing monitoring."
                ),
                severity=Severity.HIGH,
            ))
            priority_counter += 1

    # Decision
    block_triggered = (
        (has_critical and policy.get("critical_secret") == "BLOCK") or
        (has_high     and policy.get("high_vulnerability") == "BLOCK")
    )
    review_triggered = (
        (has_medium   and policy.get("medium_vulnerability") == "REVIEW") or
        (not tests_passed and policy.get("failed_tests") == "REVIEW")
    )

    if block_triggered:
        decision      = Decision.BLOCK
        risk_level    = "HIGH RISK"
        policy_passed = False
        trust_score   = min(trust_score, 30)   # cap at 30 for BLOCK
    elif review_triggered:
        decision      = Decision.REVIEW
        risk_level    = "MEDIUM RISK"
        policy_passed = False
        trust_score   = min(trust_score, 65)
    else:
        decision      = Decision.APPROVE
        risk_level    = "LOW RISK"
        policy_passed = True
        trust_score   = max(trust_score, 80)   # floor at 80 for APPROVE

    if not reasons:
        reasons.append("All security checks passed — no findings detected")
    if tests_ran and tests_passed:
        reasons.append("Functional tests PASSED")

    if decision == Decision.APPROVE:
        reasons.append("→ Policy PASSED: software meets trust requirements")
    else:
        reasons.append("→ Policy FAILED: software does NOT meet trust requirements")

    pol = PolicyResult(passed=policy_passed, reasons=reasons)

    # Sort recommendations: CRITICAL/HIGH first, then by priority
    sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    recommendations.sort(key=lambda r: (sev_order.get(r.severity, 5), r.priority))
    # Re-number after sort
    for i, r in enumerate(recommendations):
        r.priority = i + 1

    return decision, risk_level, trust_score, reasons, pol, recommendations
