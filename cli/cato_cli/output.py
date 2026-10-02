"""
Rich terminal output for CATO CLI.
Produces the output format:

  CATO Analysis — my-project
  ──────────────────────────
  Secrets        ✓ PASS
  SAST           ✗ 2 findings
  Dependencies   ✓ PASS
  Requirements   ✓ PASS
  Architecture   ✓ PASS
  Tests          ✓ PASS

  Decision:    REVIEW
  Risk:        MEDIUM RISK
  Trust Score: 72/100
  Certificate: CATO-20261002-A1B2C3D4
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from cato_core.models import AnalysisResult, Decision, Severity, CheckStatus

console = Console()

_DECISION_COLOR = {
    Decision.APPROVE: "bold green",
    Decision.REVIEW:  "bold yellow",
    Decision.BLOCK:   "bold red",
}

_DECISION_ICON = {
    Decision.APPROVE: "✅",
    Decision.REVIEW:  "⚠️ ",
    Decision.BLOCK:   "🔴",
}

_SEV_COLOR = {
    Severity.CRITICAL: "red",
    Severity.HIGH:     "dark_orange",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "dim",
}


def print_result(result: AnalysisResult, verbose: bool = False) -> None:
    console.print()

    # ── Header ────────────────────────────────────────────────────────────────
    console.rule(f"[bold]CATO Analysis — {result.project_name}[/bold]")
    console.print()

    # ── Checks table ──────────────────────────────────────────────────────────
    table = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    table.add_column("Check", style="bold", width=22)
    table.add_column("Status", width=6)
    table.add_column("Detail")

    for check in result.checks:
        if check.status == CheckStatus.PASS:
            icon   = "[green]✓[/green]"
            status = "[green]PASS[/green]"
            detail = f"[dim]{check.summary}[/dim]"
        elif check.status == CheckStatus.FAIL:
            icon   = "[red]✗[/red]"
            n      = len(check.findings)
            status = f"[red]FAIL[/red]"
            detail = f"[red]{n} finding{'s' if n != 1 else ''}[/red]  [dim]{check.summary}[/dim]"
        else:
            icon   = "[dim]–[/dim]"
            status = "[dim]SKIP[/dim]"
            detail = f"[dim]{check.summary}[/dim]"

        table.add_row(check.check_name, f"{icon} {status}", detail)

    console.print(table)

    # ── Decision banner ───────────────────────────────────────────────────────
    color = _DECISION_COLOR[result.decision]
    icon  = _DECISION_ICON[result.decision]
    score_bar = _score_bar(result.trust_score)

    console.print(Panel(
        f"{icon}  [{color}]{result.decision.value}[/{color}]   "
        f"[dim]{result.risk_level}[/dim]   "
        f"Trust Score: [{color}]{result.trust_score}/100[/{color}]  {score_bar}\n"
        f"[dim]Certificate: {result.certificate_id or 'N/A'}[/dim]",
        expand=False,
        border_style=color.replace("bold ", ""),
    ))

    # ── Findings detail (verbose or failures) ─────────────────────────────────
    findings_to_show = []
    for check in result.checks:
        for f in check.findings:
            if verbose or f.severity in (Severity.CRITICAL, Severity.HIGH):
                findings_to_show.append((check.check_name, f))

    if findings_to_show:
        console.print()
        console.print("[bold]Findings[/bold]")
        for check_name, f in findings_to_show:
            sev_color = _SEV_COLOR.get(f.severity, "white")
            loc = f"  [dim]{f.location}[/dim]" if f.location else ""
            console.print(
                f"  [{sev_color}]{f.severity.value:<8}[/{sev_color}]  "
                f"[bold]{f.title}[/bold]{loc}"
            )
            console.print(f"           [dim]{f.description}[/dim]")

    # ── Top recommendations ───────────────────────────────────────────────────
    top_recs = [r for r in result.recommendations
                if r.severity in (Severity.CRITICAL, Severity.HIGH)][:3]
    if top_recs:
        console.print()
        console.print("[bold]Top Fixes[/bold]")
        for rec in top_recs:
            sev_color = _SEV_COLOR.get(rec.severity, "white")
            console.print(f"  #{rec.priority} [{sev_color}]{rec.severity.value}[/{sev_color}]  {rec.title}")
            console.print(f"     [dim]{rec.fix[:120]}[/dim]")

    # ── Timing ────────────────────────────────────────────────────────────────
    if verbose and result.post_ai_total_ms:
        console.print()
        console.print(f"[dim]Scan completed in {result.post_ai_total_ms:.0f}ms "
                      f"across {result.files_scanned} file(s)[/dim]")

    console.print()


def _score_bar(score: int, width: int = 10) -> str:
    filled = round(score / 100 * width)
    bar    = "█" * filled + "░" * (width - filled)
    color  = "green" if score >= 80 else "yellow" if score >= 50 else "red"
    return f"[{color}]{bar}[/{color}]"
