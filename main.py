import argparse
import email
import email.policy
from pathlib import Path
from bs4 import BeautifulSoup

from rich.console import Console
from rich.table import Table
from rich.text import Text as RichText
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn
)

from detector.rules import (
    detect_auth_header_failures,
    detect_hidden_keyword_stuffing,
    detect_gibberish_strings,
    detect_url_mismatch
)

console = Console(force_terminal=True)


def parse_email_file(file_path):
    """Extracts message object, HTML, and plain text payloads from an .eml file."""
    # noinspection PyBroadException
    try:
        with open(file_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=email.policy.default)

        html_content = ""
        plain_text = ""

        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/html":
                html_content += part.get_content()
            elif content_type == "text/plain":
                plain_text += part.get_content()

        return msg, html_content, plain_text
    except Exception:
        return None, "", ""


def calculate_obfuscation_probability(results):
    """Calculates threat probability score based on heuristic triggers."""
    probability = 0

    for result in results:
        if result.get("detected"):
            reason = result["reason"]
            if "Hidden HTML structures" in reason:
                probability += 50 if result["severity"] == "HIGH" else 25
            elif "Randomized evasion strings" in reason:
                probability += 25 if result["severity"] == "HIGH" else 15
            elif "authentication failures" in reason:
                probability += 30 if result["severity"] == "HIGH" else 15
            elif "URL text does not match" in reason:
                probability += 15

    return min(probability, 99)


def format_auth_status_str(status_dict):
    """Formats SPF, DKIM, DMARC status into color-coded string tags."""
    formatted = []
    for proto in ["spf", "dkim", "dmarc"]:
        val = status_dict.get(proto, "NOT_FOUND")
        if val in ["FAIL", "SOFTFAIL"]:
            color = "bold red"
        elif val == "PASS":
            color = "bold green"
        else:
            color = "dim white"
        formatted.append(f"{proto.upper()}: [{color}]{val}[/{color}]")
    return " | ".join(formatted)


def get_color_for_probability(prob):
    if prob >= 70:
        return "bold red"
    elif prob >= 40:
        return "bold yellow"
    elif prob > 0:
        return "bold cyan"
    return "dim white"


def main():
    parser = argparse.ArgumentParser(
        description="Scan EML files for phishing, authentication failures, and keyword stuffing."
    )
    parser.add_argument(
        "-d", "--directory",
        type=Path,
        required=True,
        help="Path to directory containing .eml files"
    )
    args = parser.parse_args()

    dataset_path: Path = args.directory

    if not dataset_path.exists() or not dataset_path.is_dir():
        console.print(f"[bold red]Error:[/bold red] Directory '{dataset_path}' does not exist.")
        exit(1)

    eml_files = list(dataset_path.rglob("*.eml"))

    if not eml_files:
        console.print(f"[bold yellow]No .eml files found in '{dataset_path.resolve()}'.[/bold yellow]")
        exit(0)

    console.print(
        f"[bold blue]Starting EML Detection Engine on target:[/bold blue] [yellow]{dataset_path.resolve()}[/yellow]\n")

    # Table for high-level summary
    table = Table(title="Detection Engine Summary", show_header=True, header_style="bold magenta")
    table.add_column("File Name", style="cyan")
    table.add_column("Threat Score", justify="right")
    table.add_column("Auth Status (SPF | DKIM | DMARC)")
    table.add_column("Primary Indicators")

    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=False
    ) as progress:

        scan_task = progress.add_task("[cyan]Scanning EML files...", total=len(eml_files))

        for file in eml_files:
            progress.update(scan_task, description=f"[cyan]Scanning [bold]{file.name}[/bold]")

            msg, html, text = parse_email_file(file)
            soup = BeautifulSoup(html, 'html.parser') if html else None
            combined_text = (html + " " + text)

            auth_res = detect_auth_header_failures(msg)
            results = [
                auth_res,
                detect_hidden_keyword_stuffing(soup),
                detect_gibberish_strings(combined_text),
                detect_url_mismatch(soup)
            ]

            prob = calculate_obfuscation_probability(results)
            color = get_color_for_probability(prob)

            active_indicators = []
            file_detections = []

            for r in results:
                if r.get("detected"):
                    active_indicators.extend(r["indicators"])
                    file_detections.append(r)

            auth_status_text = format_auth_status_str(auth_res["status"])

            # Live print detailed detection panel for high threat probability
            if prob >= 40:
                alert_text = RichText()
                alert_text.append("Threat Score: ", style="bold")
                alert_text.append(f"{prob}%\n", style=color)
                alert_text.append("Auth Check: ", style="bold")
                alert_text.append(
                    f"SPF: {auth_res['status']['spf']} | "
                    f"DKIM: {auth_res['status']['dkim']} | "
                    f"DMARC: {auth_res['status']['dmarc']}\n"
                )

                for r in file_detections:
                    alert_text.append(f"\n[{r['severity']}] {r['reason']}\n", style="bold")
                    alert_text.append(f"Indicators: {', '.join(r['indicators'])}")

                panel = Panel(
                    alert_text,
                    title=f"[{color}]DETECTION: {file.name}[/{color}]",
                    border_style=color.split()[-1]
                )
                progress.console.print(panel)
                progress.console.print()

            # Add entry to summary table
            indicator_summary = ", ".join(active_indicators[:2]) + ("..." if len(active_indicators) > 2 else "")
            table.add_row(
                file.name,
                f"[{color}]{prob}%[/{color}]",
                auth_status_text,
                indicator_summary if indicator_summary else "Clean"
            )

            progress.advance(scan_task)

    console.print("\n")
    console.print(table)


if __name__ == "__main__":
    main()