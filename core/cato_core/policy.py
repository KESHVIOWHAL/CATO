"""
Policy loader — reads cato-policy.json from a project directory,
falls back to sensible defaults if not present.
"""

import json
from pathlib import Path
from typing import Any, Dict

DEFAULT_POLICY: Dict[str, Any] = {
    "critical_secret": "BLOCK",
    "high_vulnerability": "BLOCK",
    "medium_vulnerability": "REVIEW",
    "failed_tests": "REVIEW",
}


def load_policy(project_path: Path) -> Dict[str, Any]:
    """Return merged policy: defaults overridden by cato-policy.json if present."""
    policy_file = project_path / "cato-policy.json"
    if policy_file.exists():
        try:
            overrides = json.loads(policy_file.read_text(encoding="utf-8"))
            return {**DEFAULT_POLICY, **overrides}
        except Exception:
            pass
    return dict(DEFAULT_POLICY)
