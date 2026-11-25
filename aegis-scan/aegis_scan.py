"""AegisScan CLI & Interactive Educational Port Scanner."""

import argparse
import sys
from typing import Optional

from scanner.core import run_scan
from scanner.intel import PRESETS, parse_ports
from scanner.reporter import (
    Palette,
    export_html,
    export_json,
    print_banner,
    print_learning_guide,
    print_summary,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis_scan",
        description="AegisScan: Educational multi-threaded TCP port scanner with banner grabbing & risk insights.",
        epilog="Example: python aegis_scan.py 127.0.0.1 --ports quick --learn --out report.html",
    )
    parser.add_argument("target", nargs="?", help="Target IP address or hostname (e.g. 127.0.0.1)")
    parser.add_argument(
        "-p",
        "--ports",
        default="quick",
        help="Ports: 'quick', 'web', 'db', 'top100', 'full', or custom e.g. '22,80,443,8000-8010' (default: quick)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=100,
        help="Number of concurrent worker threads (default: 100)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.8,
        help="Socket timeout in seconds per port (default: 0.8)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner grabbing and TLS certificate inspection (faster)",
    )
    parser.add_argument(
        "--learn",
        action="store_true",
        help="Display a beginner-friendly explanation of how the scan works",
    )
    parser.add_argument(
        "-o",
        "--out",
        help="Save report to a .json or .html file (e.g. report.html)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI terminal colors",
    )
    return parser


def interactive_prompt(pal: Palette) -> argparse.Namespace:
    """Guide beginners through choosing scan options interactively."""
    print(pal.bold("  Interactive Mode (No CLI flags provided)"))
    print("  Available presets:", ", ".join(PRESETS.keys()), "or 'full' (1-65535)")
    target = input("  Enter target IP/hostname [127.0.0.1]: ").strip() or "127.0.0.1"
    ports = input("  Enter ports or preset [quick]: ").strip() or "quick"
    learn_ans = input("  Show how port scanning works? (y/N): ").strip().lower()
    out = input("  Save HTML/JSON report path (leave blank to skip): ").strip() or None

    return argparse.Namespace(
        target=target,
        ports=ports,
        threads=100,
        timeout=0.8,
        no_banner=False,
        learn=learn_ans in {"y", "yes"},
        out=out,
        no_color=False,
    )


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    pal = Palette(enabled=not args.no_color)
    print_banner(pal)

    if not args.target:
        try:
            args = interactive_prompt(pal)
        except (EOFError, KeyboardInterrupt):
            print("\n  Cancelled.")
            return 1

    if args.learn:
        print_learning_guide(pal)

    try:
        port_list = parse_ports(args.ports)
    except ValueError as exc:
        print(pal.red(f"  [Error] {exc}"))
        return 2

    print(f"  Scanning {pal.cyan(args.target)} across {len(port_list)} port(s) with {args.threads} threads...")

    def show_progress(done: int, total: int) -> None:
        if sys.stdout.isatty():
            pct = int((done / total) * 100)
            sys.stdout.write(f"\r  Progress: [{done}/{total}] {pct}%")
            sys.stdout.flush()

    try:
        summary = run_scan(
            target=args.target,
            ports=port_list,
            threads=args.threads,
            timeout=args.timeout,
            grab_banners=not args.no_banner,
            progress_cb=show_progress,
        )
    except ValueError as exc:
        print(pal.red(f"\n  [Error] {exc}"))
        return 2
    except KeyboardInterrupt:
        print(pal.yellow("\n  [!] Scan interrupted by user."))
        return 130

    if sys.stdout.isatty():
        print()  # Newline after progress indicator

    print_summary(summary, pal)

    if args.out:
        out_lower = args.out.lower()
        if out_lower.endswith(".json"):
            export_json(summary, args.out)
        elif out_lower.endswith(".html") or out_lower.endswith(".htm"):
            export_html(summary, args.out)
        else:
            print(pal.yellow("  [!] Unrecognized extension; saving as JSON."))
            export_json(summary, args.out)
        print(pal.green(f"  [+] Report saved to: {args.out}\n"))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
