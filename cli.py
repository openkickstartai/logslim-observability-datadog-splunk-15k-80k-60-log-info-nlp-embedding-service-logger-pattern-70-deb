"""LogSlim CLI — Log cost attribution from your terminal."""
import sys
import json
import click
from rich.console import Console
from rich.table import Table
from logslim import analyze, analyze_with_store, DEFAULT_RATE


console = Console()


@click.command()
@click.argument('logfile', type=click.Path(exists=True), required=False)
@click.option('--rate', default=DEFAULT_RATE, type=float, help='Cost per GB ingested in USD (default: 0.10 for Datadog)')
@click.option('--top', default=15, type=int, help='Show top N patterns')
@click.option('--min-noise', default=0, type=float, help='Only show patterns with noise score >= threshold')
@click.option('--db-path', default=None, type=click.Path(), help='DuckDB file path (default: ~/.logslim/cache.duckdb)')
def main(logfile, rate, top, json_out, min_noise, db_path):

def main(logfile, rate, top, json_out, min_noise):
    """LogSlim — Find which log patterns are burning your observability budget.

    Provide a LOGFILE path or pipe logs via stdin.
    """
    if logfile:
        with open(logfile, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    elif not sys.stdin.isatty():
        lines = sys.stdin.readlines()
    else:
        console.print("[red]Error:[/red] Provide a log file or pipe logs via stdin.")
    result = analyze_with_store(lines, rate_per_gb=rate, db_path=db_path, source_file=logfile)

        console.print("         cat logs/*.log | python cli.py")
        raise SystemExit(1)
    result = analyze(lines, rate_per_gb=rate)
    if json_out:
        click.echo(json.dumps(result, indent=2, default=str))
        return
    _render(result, top, min_noise)


def _render(result, top, min_noise):
    patterns = [p for p in result['patterns'] if p['noise_score'] >= min_noise][:top]
    console.print(f"\n[bold cyan]━━━ LogSlim Analysis ━━━[/bold cyan]")
    total_lines = sum(p['count'] for p in result['patterns'])
    console.print(f"  Lines: {total_lines:,}  |  Patterns: {result['pattern_count']}  |  "
                  f"Volume: {result['total_bytes'] / 1e6:.2f} MB  |  "
                  f"Est. Cost: [bold]${result['total_cost']:.4f}[/bold]/period\n")
    table = Table(title="Top Patterns by Cost", show_lines=False)
    for col in ["#", "Pattern", "Count", "Size", "Cost", "%Vol", "Noise", "Level", "Services"]:
        table.add_column(col, no_wrap=(col in ("#", "Count", "Size", "Cost", "%Vol", "Noise")))
    for i, p in enumerate(patterns, 1):
        nc = "red" if p['noise_score'] >= 50 else "yellow" if p['noise_score'] >= 25 else "green"
        top_level = max(p['levels'], key=p['levels'].get) if p['levels'] else '-'
        table.add_row(
            str(i), p['pattern'][:55], f"{p['count']:,}",
            f"{p['bytes'] / 1024:.0f}KB", f"${p['cost']:.6f}", f"{p['pct']:.1f}%",
            f"[{nc}]{p['noise_score']}[/{nc}]", top_level, ",".join(p['services'][:3]))
    console.print(table)
    recs = result['recommendations']
    if recs:
        console.print(f"\n[bold yellow]💡 Recommendations ({len(recs)})[/bold yellow]")
        total_sav = 0.0
        for r in recs:
            icon = {"DROP_OR_SAMPLE": "🗑️", "RAISE_LOG_LEVEL": "⬆️", "TRIM_FIELDS": "✂️"}.get(r['action'], "•")
            console.print(f"  {icon}  [{r['action']}] {r['pattern'][:50]}")
            console.print(f"     {r['reason']}  →  est. savings: {r['est_savings_pct']}%")
            total_sav += r['est_savings_pct']
        console.print(f"\n  [bold green]🎯 Total potential savings: ~{min(total_sav, 95):.0f}% "
                      f"(≈ ${result['total_cost'] * min(total_sav, 95) / 100:.4f}/period)[/bold green]")
    else:
        console.print("\n  [green]✅ No high-noise patterns detected. Your logs look clean![/green]")


if __name__ == '__main__':
    main()
