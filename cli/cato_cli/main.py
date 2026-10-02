"""
CATO CLI — cato analyze .

Usage:
  cato analyze .
  cato analyze /path/to/project --verbose
  cato analyze . --context "Payment API handling PCI-DSS data"
  cato report <scan-id>        (future: pulls from API)
"""

import sys
from pathlib import Path

import click
from rich.console import Console

from cato_core.engine import run_analysis
from cato_core.models import Decision
from .output import print_result, console


@click.group()
@click.version_option("0.1.0", prog_name="cato")
def cli():
    """CATO — Context-Aware Trust Orchestrator"""


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option("--name",    "-n", default=None,  help="Project name (defaults to directory name)")
@click.option("--context", "-c", default="",    help="Architecture / requirement context")
@click.option("--verbose", "-v", is_flag=True,  help="Show all findings and timing")
@click.option("--json",    "-j", is_flag=True,  help="Output raw JSON result")
@click.option("--fail-on", default="BLOCK",
              type=click.Choice(["BLOCK", "REVIEW", "never"], case_sensitive=False),
              help="Exit with code 1 when decision meets this threshold (default: BLOCK)")
def analyze(path: str, name: str, context: str, verbose: bool, json: bool, fail_on: str):
    """Run CATO security analysis on a project directory."""
    project_path = Path(path).resolve()
    project_name = name or project_path.name

    if not json:
        console.print(f"[dim]Scanning [bold]{project_name}[/bold] at {project_path}…[/dim]")

    try:
        result = run_analysis(project_path, project_name, context)
    except Exception as exc:
        console.print(f"[red]Error running analysis: {exc}[/red]")
        sys.exit(2)

    if json:
        import json as _json
        click.echo(_json.dumps(result.model_dump(), indent=2, default=str))
    else:
        print_result(result, verbose=verbose)

    # Exit code logic
    should_fail = False
    if fail_on == "BLOCK" and result.decision == Decision.BLOCK:
        should_fail = True
    elif fail_on == "REVIEW" and result.decision in (Decision.BLOCK, Decision.REVIEW):
        should_fail = True

    if should_fail:
        sys.exit(1)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False))
def init(path: str):
    """Create a default cato-policy.json in a project directory."""
    import json as _json
    policy_path = Path(path) / "cato-policy.json"
    if policy_path.exists():
        console.print(f"[yellow]cato-policy.json already exists at {policy_path}[/yellow]")
        return
    default = {
        "critical_secret":      "BLOCK",
        "high_vulnerability":   "BLOCK",
        "medium_vulnerability": "REVIEW",
        "failed_tests":         "REVIEW",
    }
    policy_path.write_text(_json.dumps(default, indent=2))
    console.print(f"[green]Created cato-policy.json at {policy_path}[/green]")
    console.print("[dim]Edit this file to customize CATO's decision thresholds.[/dim]")
