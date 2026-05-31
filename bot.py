"""
bot.py
══════════════════════════════════════════════════════════════════════════════
Discord Bot Command Listener Interface
──────────────────────────────────────────────────────────────────────────────
Exposes a non-blocking `!harvest <url>` command that runs in a native
multiprocessing.Process, and a `!stop` command to forcibly terminate active
scans mapped per channel ID.
══════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import sys

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

import asyncio
import io
import logging
import multiprocessing
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    import psutil
    _PSUTIL_AVAILABLE: bool = True
except ImportError:
    _PSUTIL_AVAILABLE = False
    logger_pre = logging.getLogger(__name__)
    logger_pre.warning("psutil not installed — !stop will only kill the supervisor process. Run: pip install psutil")

import discord
from discord.ext import commands
from dotenv import load_dotenv

from distributed_api_harvester import DistributedApiHarvester
from webhook_cleaner import WebhookCleaner

load_dotenv()

# Env variables
BOT_TOKEN: str = os.getenv("DISCORD_BOT_TOKEN", "")
WEBHOOK_URL: str = os.getenv("DISCORD_WEBHOOK_URL", "")

DEFAULT_INSTANCES: int = 3
DEFAULT_DEPTH: int = 2

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

# Discord Setup
_intents = discord.Intents.default()
_intents.message_content = True

bot = commands.Bot(
    command_prefix="!",
    intents=_intents,
    help_command=commands.DefaultHelpCommand(),
)

# Global tracker for active running processes mapped to channel IDs
active_scans: Dict[int, multiprocessing.Process] = {}

def _validate_url(raw: str) -> Optional[str]:
    """Validate and normalize a URL string."""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        return None
    return raw.rstrip("/")

def _build_metrics_embed(
    target_url: str,
    pages_analysed: int,
    endpoints_found: int,
    elapsed: float,
    instance_count: int,
    max_depth: int,
) -> discord.Embed:
    """Construct metrics Discord Embed summary card."""
    embed = discord.Embed(
        title="✅ Harvest Complete — Intelligence Report Ready",
        description=(
            f"**Target:** `{target_url}`\n"
            f"**Report:** See attached `api_breakdown.txt`"
        ),
        color=discord.Color.from_rgb(46, 204, 113),
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(name="📄 Pages Analysed",    value=str(pages_analysed),  inline=True)
    embed.add_field(name="🔗 Endpoints Found",   value=str(endpoints_found), inline=True)
    embed.add_field(name="⏱️ Duration",           value=f"{elapsed:.1f}s",    inline=True)
    embed.add_field(name="⚙️ Processes Used",     value=str(instance_count),  inline=True)
    embed.add_field(name="🔁 Max Crawl Depth",   value=str(max_depth),       inline=True)
    embed.set_footer(text="Distributed API Harvesting Engine")
    return embed

def _build_error_embed(error_msg: str, target_url: str = "") -> discord.Embed:
    """Error display card."""
    embed = discord.Embed(
        title="❌ Harvest Failed",
        description=f"```{error_msg[:1000]}```",
        color=discord.Color.red(),
        timestamp=datetime.now(timezone.utc),
    )
    if target_url:
        embed.add_field(name="Target", value=target_url, inline=False)
    embed.set_footer(text="Distributed API Harvesting Engine")
    return embed

def _build_start_embed(target_url: str, instances: int, depth: int) -> discord.Embed:
    """Start notification card."""
    embed = discord.Embed(
        title="🚀 Harvest Started",
        description=(
            f"**Target:** `{target_url}`\n"
            f"Real-time intercept alerts will stream to the configured webhook channel.\n"
            f"The final report will be uploaded here when complete."
        ),
        color=discord.Color.blurple(),
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(name="⚙️ OS Processes",      value=str(instances), inline=True)
    embed.add_field(name="🔁 Max Crawl Depth",   value=str(depth),     inline=True)
    embed.set_footer(text="Distributed API Harvesting Engine")
    return embed

def _run_harvester_process(
    target_url: str,
    instances: int,
    depth: int,
    webhook_url: str,
    shared_state: Dict[str, Any],
) -> None:
    """Target process handler executed inside isolated Process."""
    try:
        harvester = DistributedApiHarvester(
            target_url=target_url,
            instance_count=instances,
            max_depth=depth,
            headless=True,
            webhook_url=webhook_url,
        )
        report_path = harvester.start_harvest_cycle()
        shared_state["report_path"] = report_path
        shared_state["endpoints_found"] = harvester.endpoints_found
        shared_state["pages_analysed"] = harvester.pages_analysed
        shared_state["elapsed_seconds"] = harvester.elapsed_seconds
    except Exception as exc:
        shared_state["error"] = str(exc)

@bot.event
async def on_ready() -> None:
    """Fired once authenticated."""
    assert bot.user is not None
    logger.info("Bot authenticated as %s (ID: %s)", bot.user, bot.user.id)
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name="!harvest <url> for intel",
        )
    )
    print(
        f"\n  ✓  Bot online: {bot.user}\n"
        f"  ✓  Prefix: !\n"
        f"  ✓  Commands: !harvest, !stop, !status, !help\n",
        flush=True,
    )

@bot.event
async def on_command_error(ctx: commands.Context, error: commands.CommandError) -> None:
    """Error logger."""
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(
            embed=discord.Embed(
                description="⚠️ Missing argument: `target` url.\nUsage: `!harvest <url> [instances] [depth]`",
                color=discord.Color.orange(),
            )
        )
    elif isinstance(error, commands.CommandInvokeError):
        logger.error("Command error: %s", error.original)
        await ctx.send(embed=_build_error_embed(str(error.original)))
    else:
        logger.warning("Unhandled command error: %s", error)

@bot.command(
    name="harvest",
    help="Launch a distributed API harvest on the target URL.",
)
async def harvest(
    ctx: commands.Context,
    target: str,
    instances: int = DEFAULT_INSTANCES,
    depth: int = DEFAULT_DEPTH,
) -> None:
    """Command implementation using safe process isolation monitoring."""
    validated_url = _validate_url(target)
    if not validated_url:
        await ctx.send(
            embed=discord.Embed(
                description=f"❌ Invalid URL: `{target}`\nPlease provide a valid HTTP/HTTPS address.",
                color=discord.Color.red(),
            )
        )
        return

    instances = max(1, min(instances, 10))
    depth = max(0, min(depth, 5))

    channel_id = ctx.channel.id
    if channel_id in active_scans:
        await ctx.send(
            embed=discord.Embed(
                description="⏳ A harvest is already running in this channel. Use `!stop` to cancel it.",
                color=discord.Color.orange(),
            )
        )
        return

    await ctx.send(embed=_build_start_embed(validated_url, instances, depth))
    logger.info("Harvest process started for target: %s", validated_url)

    # Spawn harvester inside a Process
    manager = multiprocessing.Manager()
    shared_state = manager.dict()

    p = multiprocessing.Process(
        target=_run_harvester_process,
        args=(validated_url, instances, depth, WEBHOOK_URL, shared_state)
    )
    
    # Save p to the global tracking dictionary before starting
    active_scans[channel_id] = p
    p.start()

    try:
        # Non-blocking state monitoring
        while p.is_alive():
            await asyncio.sleep(1.5)

        p.join()

        # If it was forcibly terminated via !stop command, skip clean finish output
        if channel_id not in active_scans:
            return

        # Error checks
        if "error" in shared_state:
            err_msg = shared_state["error"]
            logger.error("Harvest process error: %s", err_msg)
            await ctx.send(embed=_build_error_embed(err_msg, validated_url))
            return

        report_path = shared_state.get("report_path", "")
        endpoints_found = shared_state.get("endpoints_found", 0)
        pages_analysed = shared_state.get("pages_analysed", 0)
        elapsed_seconds = shared_state.get("elapsed_seconds", 0.0)

        metrics_embed = _build_metrics_embed(
            target_url=validated_url,
            pages_analysed=pages_analysed,
            endpoints_found=endpoints_found,
            elapsed=elapsed_seconds,
            instance_count=instances,
            max_depth=depth,
        )

        try:
            with open(report_path, "rb") as report_fh:
                report_bytes = report_fh.read()

            report_file = discord.File(
                fp=io.BytesIO(report_bytes),
                filename="api_breakdown.txt",
                description="API Harvest Intelligence Report",
            )
            await ctx.send(embed=metrics_embed, file=report_file)
            logger.info("Crawl completed successfully and report uploaded.")
        except Exception as exc:
            logger.error("Report read/upload failure: %s", exc)
            await ctx.send(embed=metrics_embed, content=f"⚠️ Failed to attach report file: {exc}")

        # Post wrap-up alerts to webhook
        await WebhookCleaner.dispatch_summary_card(
            webhook_url=WEBHOOK_URL,
            target_url=validated_url,
            pages_analysed=pages_analysed,
            endpoints_found=endpoints_found,
            elapsed_seconds=elapsed_seconds,
            instance_count=instances,
        )
    finally:
        active_scans.pop(channel_id, None)
        manager.shutdown()

@bot.command(
    name="stop",
    help="Force-stop the active API harvest in the current channel.",
)
async def stop(ctx: commands.Context) -> None:
    """Force-stop the active API harvest scan in the channel."""
    channel_id = ctx.channel.id
    if channel_id not in active_scans:
        await ctx.send(
            embed=discord.Embed(
                description="❌ No active harvest scan running in this channel.",
                color=discord.Color.red(),
            )
        )
        return

    # Remove from tracking dict first so the monitor loop exits cleanly
    p = active_scans.pop(channel_id, None)
    if not (p and p.is_alive()):
        await ctx.send(
            embed=discord.Embed(
                description="⚠️ Process was already finished.",
                color=discord.Color.orange(),
            )
        )
        return

    killed: List[str] = []

    # ── Step 1: Kill the full grandchild process tree via psutil ─────────
    if _PSUTIL_AVAILABLE:
        try:
            parent = psutil.Process(p.pid)
            children: List[psutil.Process] = parent.children(recursive=True)
            for child in children:
                try:
                    child.terminate()
                    killed.append(str(child.pid))
                except psutil.NoSuchProcess:
                    pass
            # Give up to 3 s for graceful shutdown
            _, alive = psutil.wait_procs(children, timeout=3)
            for child in alive:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
        except psutil.NoSuchProcess:
            pass
        except Exception as exc:
            logger.warning("psutil tree-kill error: %s", exc)

    # ── Step 2: Terminate the supervisor process itself ───────────────────
    try:
        p.terminate()
        p.join(timeout=5)
        if p.is_alive():
            p.kill()
            p.join(timeout=3)
    except Exception as exc:
        logger.warning("Supervisor termination error: %s", exc)

    tree_info = f" (killed PIDs: {', '.join(killed)})" if killed else ""
    await ctx.send(
        embed=discord.Embed(
            description=(
                f"🛑 **Harvest Stopped**: All browser instances have been forcibly terminated.{tree_info}"
            ),
            color=discord.Color.red(),
            timestamp=datetime.now(timezone.utc),
        )
    )

@bot.command(name="status", help="Check system status.")
async def status(ctx: commands.Context) -> None:
    """Report engine status."""
    channel_id = ctx.channel.id
    if channel_id in active_scans:
        embed = discord.Embed(
            description="🔄 **Status:** Harvest in progress in this channel.",
            color=discord.Color.orange(),
        )
    else:
        embed = discord.Embed(
            description="✅ **Status:** Engine is idle and ready.",
            color=discord.Color.green(),
        )
    embed.set_footer(text="Distributed API Harvesting Engine")
    await ctx.send(embed=embed)

def main() -> None:
    """Start Discord commands listener."""
    multiprocessing.freeze_support()
    if not BOT_TOKEN or "YOUR_DISCORD_BOT_TOKEN_PLACEHOLDER" in BOT_TOKEN:
        print("ERROR: DISCORD_BOT_TOKEN is not configured in .env", file=sys.stderr)
        sys.exit(1)

    print(
        "\n  Distributed API Harvesting Engine — Discord Bot\n"
        f"  Token  : {'*' * 20}{BOT_TOKEN[-6:]}\n"
        f"  Webhook: {'configured' if WEBHOOK_URL else 'NOT SET'}\n",
        flush=True,
    )

    try:
        bot.run(BOT_TOKEN, log_handler=None)
    except discord.LoginFailure:
        print("ERROR: Authentication failed.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n  Bot stopped.", flush=True)

if __name__ == "__main__":
    multiprocessing.set_start_method("spawn", force=True)
    main()
