"""
main.py
══════════════════════════════════════════════════════════════════════════════
CLI Entry Point — No-Discord Standalone Mode
──────────────────────────────────────────────────────────────────────────────
Run the full distributed API harvest pipeline directly from the terminal
without needing a Discord bot or webhook.

All harvested intelligence is written to `api_breakdown.txt`.
Real-time webhook alerts are sent if DISCORD_WEBHOOK_URL is set in .env.

Usage
─────
    python main.py
    python main.py --url https://example.com
    python main.py --url https://example.com --instances 5 --depth 3
    python main.py --url https://example.com --instances 2 --headed
    python main.py --url https://example.com --quiet

For Discord Bot mode, run `bot.py` instead:
    python bot.py
══════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import argparse
import logging
import multiprocessing
import os
import sys
from typing import Optional
from urllib.parse import urlparse

# Configure console stdout/stderr to use UTF-8 to prevent UnicodeEncodeError on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from dotenv import load_dotenv

from distributed_api_harvester import DistributedApiHarvester

load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# Console styling
# ─────────────────────────────────────────────────────────────────────────────

_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


def _banner() -> None:
    print(f"""
{_CYAN}{_BOLD}╔══════════════════════════════════════════════════════════════════════════╗
║   DISTRIBUTED MULTI-INSTANCE ASYNC API DISCOVERY & HARVESTING ENGINE    ║
║   stealth.py  x  api_discovery_crawler.py  x  distributed_api_harvester ║
║   webhook_cleaner.py  x  Standalone CLI Mode (no Discord required)       ║
╚══════════════════════════════════════════════════════════════════════════╝{_RESET}
""")


def _info(msg: str)    -> None: print(f"  {_CYAN}i{_RESET}  {msg}")
def _success(msg: str) -> None: print(f"  {_GREEN}v{_RESET}  {msg}")
def _warn(msg: str)    -> None: print(f"  {_YELLOW}!{_RESET}  {msg}")
def _error(msg: str)   -> None: print(f"  {_RED}x{_RESET}  {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# Argument Parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Distributed Multi-Instance Async API Discovery & Harvesting Engine (CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py\n"
            "  python main.py --url https://example.com\n"
            "  python main.py --url https://example.com --instances 5 --depth 3\n"
            "  python main.py --url https://example.com --instances 2 --headed\n"
            "\n"
            "For Discord Bot mode:\n"
            "  python bot.py\n"
        ),
    )
    parser.add_argument(
        "--url", type=str, default=None,
        help="Target base URL (prompted if omitted).",
    )
    parser.add_argument(
        "--instances", type=int, default=None,
        help="Number of OS worker processes (1-20, default 3).",
    )
    parser.add_argument(
        "--depth", type=int, default=None,
        help="Maximum crawl depth (0-10, default 2).",
    )
    parser.add_argument(
        "--headed", action="store_true", default=False,
        help="Run browsers in headed (visible) mode.",
    )
    parser.add_argument(
        "--quiet", action="store_true", default=False,
        help="Suppress verbose INFO logs.",
    )
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Input Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _prompt_url(provided: Optional[str]) -> str:
    """Validate or interactively prompt for a target URL."""
    url: str = provided or ""
    while not url.strip():
        url = input(f"  {_BOLD}Enter target URL:{_RESET} ").strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if not parsed.hostname:
        _error("Invalid URL — cannot extract hostname.")
        sys.exit(1)

    return url.rstrip("/")


def _prompt_int(
    provided:    Optional[int],
    prompt_text: str,
    default:     int,
    min_val:     int,
    max_val:     int,
) -> int:
    """Validate or interactively prompt for an integer within [min_val, max_val]."""
    if provided is not None:
        if min_val <= provided <= max_val:
            return provided
        _warn(f"Value {provided} out of range [{min_val},{max_val}]. Using default: {default}.")
        return default

    while True:
        raw: str = input(f"  {_BOLD}{prompt_text} (default {default}):{_RESET} ").strip()
        if not raw:
            return default
        try:
            val = int(raw)
            if min_val <= val <= max_val:
                return val
            _warn(f"Please enter a number between {min_val} and {max_val}.")
        except ValueError:
            _warn("Please enter a valid integer.")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Validate inputs and run the full distributed harvest pipeline."""
    multiprocessing.freeze_support()

    _banner()
    args = _parse_args()

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )

    # ── Resolve inputs ─────────────────────────────────────────────────────
    target_url: str = _prompt_url(args.url)

    instance_count: int = _prompt_int(
        provided=args.instances,
        prompt_text="Number of OS processes",
        default=3, min_val=1, max_val=20,
    )

    max_depth: int = _prompt_int(
        provided=args.depth,
        prompt_text="Maximum crawl depth",
        default=2, min_val=0, max_val=10,
    )

    headless: bool  = not args.headed
    webhook_url: str = os.getenv("DISCORD_WEBHOOK_URL", "")

    # ── Print config ───────────────────────────────────────────────────────
    print()
    _info(f"Target URL    : {target_url}")
    _info(f"Instances     : {instance_count} OS processes")
    _info(f"Max Depth     : {max_depth}")
    _info(f"Headless      : {headless}")
    _info(f"Webhook       : {'configured' if webhook_url else 'not set (alerts disabled)'}")
    _info(f"Report Output : {os.path.abspath('api_breakdown.txt')}")
    print()

    # ── Launch ────────────────────────────────────────────────────────────
    harvester = DistributedApiHarvester(
        target_url=target_url,
        instance_count=instance_count,
        max_depth=max_depth,
        headless=headless,
        webhook_url=webhook_url,
    )

    try:
        # start_harvest_cycle() is the correct method name on DistributedApiHarvester
        report_path: str = harvester.start_harvest_cycle()
    except KeyboardInterrupt:
        _warn("Interrupted — partial results may have been saved.")
        sys.exit(0)
    except Exception as exc:
        _error(f"Harvest failed: {exc}")
        raise

    # ── Summary ────────────────────────────────────────────────────────────
    print()
    _success(f"Harvest complete in {harvester.elapsed_seconds:.1f}s")
    _success(f"Pages analysed  : {harvester.pages_analysed}")
    _success(f"Endpoints found : {harvester.endpoints_found}")
    _success(f"Report saved    : {os.path.abspath(report_path)}")
    print()


if __name__ == "__main__":
    multiprocessing.set_start_method("spawn", force=True)
    main()
