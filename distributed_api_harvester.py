"""
distributed_api_harvester.py
══════════════════════════════════════════════════════════════════════════════
Multiprocessing Supervisor & Report Generator
──────────────────────────────────────────────────────────────────────────────
Spawns N isolated OS processes, each running one persistent async event loop.
Shares tasks using multiprocessing Manager Queues, Lock, and Dicts with
robust anti-trap, normalization, and politeness delay safety features.
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
import logging
import multiprocessing
import os
import random
import signal
import time
from collections import defaultdict
from datetime import datetime, timezone
from multiprocessing.managers import SyncManager
from queue import Empty
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse

from dotenv import load_dotenv
from api_discovery_crawler import ApiDiscoveryCrawler, ApiEndpoint, CrawlResult

load_dotenv()
logger = logging.getLogger(__name__)

# Constants
REPORT_FILENAME: str = "api_breakdown.txt"
QUEUE_GET_TIMEOUT: float = 4.0
WORKER_IDLE_LIMIT: int = 5
WEBHOOK_URL: str = os.getenv("DISCORD_WEBHOOK_URL", "")

def normalize_url(url: str) -> str:
    """
    Normalise URLs strictly:
      - Force lowercase.
      - Remove trailing slashes.
      - Strip tracking flags (utm_*, gclid, fbclid, affiliate, ref).
      - Remove hash fragments.
    """
    url = url.strip().lower()
    parsed = urlparse(url)
    
    # Strip tracking parameters
    query_params = parse_qs(parsed.query)
    clean_params = {}
    for k, v in query_params.items():
        if k.startswith("utm_") or k in ("gclid", "fbclid", "affiliate", "ref"):
            continue
        clean_params[k] = v
        
    new_query = urlencode(clean_params, doseq=True)
    clean_path = parsed.path.rstrip("/")
    if not clean_path:
        clean_path = ""
        
    new_parsed = parsed._replace(path=clean_path, query=new_query, fragment="")
    return new_parsed.geturl()

def is_crawler_trap(url: str) -> bool:
    """Filter out crawler traps and infinite loop URLs containing specified query tokens."""
    url_lower = url.lower()
    # Trap tokens
    trap_tokens = ("?page=", "&sort=", "view=")
    return any(token in url_lower for token in trap_tokens)

def _endpoint_to_dict(ep: ApiEndpoint) -> Dict[str, Any]:
    """Convert dataclass endpoint record into plain dict for multiprocess IPC."""
    return {
        "parent_page":      ep.parent_page,
        "url":              ep.url,
        "method":           ep.method,
        "status_code":      ep.status_code,
        "content_type":     ep.content_type,
        "requires_auth":    ep.requires_auth,
        "auth_description": ep.auth_description,
        "query_params":     ep.query_params,
        "payload_keys":     ep.payload_keys,
        "signal_type":      ep.signal_type,
    }

async def async_process_loop(
    instance_id: int,
    worker_id: int,
    task_queue: Any,
    result_list: Any,
    visited_map: Any,
    visited_lock: Any,
    max_depth: int,
    headless: bool,
    webhook_url: str,
) -> None:
    """Asynchronous core navigation worker loop for independent OS processes."""
    prefix = f"[Instance-{instance_id}][Worker-{worker_id}]"

    def _log(msg: str) -> None:
        line = f"{prefix} {msg}"
        print(line, flush=True)
        logger.info(line)

    _log("Async process loop started.")
    crawler = ApiDiscoveryCrawler(
        instance_id=instance_id,
        worker_id=worker_id,
        headless=headless,
        webhook_url=webhook_url,
    )

    try:
        await crawler.start()
    except Exception as exc:
        _log(f"ERROR: Failed to launch browser context: {exc}")
        return

    idle_streak: int = 0

    try:
        while idle_streak < WORKER_IDLE_LIMIT:
            try:
                url, depth = task_queue.get(timeout=QUEUE_GET_TIMEOUT)
                idle_streak = 0
            except Empty:
                idle_streak += 1
                _log(f"Queue idle ({idle_streak}/{WORKER_IDLE_LIMIT}) — holding warm for new routes…")
                continue

            # Atomic visited map checking/setting using Lock
            with visited_lock:
                norm = normalize_url(url)
                
                # Check traps
                if is_crawler_trap(norm):
                    _log(f"Skipping crawler trap: {url}")
                    task_queue.task_done()
                    continue
                
                # Enforce safety cap of 50 pages per run
                if len(visited_map) >= 50:
                    _log("Visited map hard safety cap (50) reached. Ignoring URL.")
                    task_queue.task_done()
                    continue

                if norm in visited_map:
                    task_queue.task_done()
                    continue
                
                visited_map[norm] = True

            # Randomized politeness delay (1.0 to 5.0 seconds) to bypass strict anti-bot WAFs
            delay = random.uniform(1.0, 5.0)
            _log(f"Politeness delay of {delay:.2f}s before opening {url}")
            await asyncio.sleep(delay)

            try:
                result: CrawlResult = await crawler.crawl_page(
                    url=url,
                    base_domain=urlparse(url).hostname or "",
                    depth=depth,
                    max_depth=max_depth,
                )
            except Exception as exc:
                _log(f"Crawl process failed for {url}: {exc}")
                task_queue.task_done()
                continue

            for ep in result.endpoints:
                try:
                    result_list.append(_endpoint_to_dict(ep))
                except Exception as exc:
                    _log(f"WARNING: Shared results list IPC append failed: {exc}")

            # Queue discovery children routes
            if depth < max_depth:
                for child_url in result.child_links:
                    child_norm = normalize_url(child_url)
                    with visited_lock:
                        already_seen = child_norm in visited_map
                        cap_reached = len(visited_map) >= 50
                    
                    if not already_seen and not cap_reached and not is_crawler_trap(child_norm):
                        try:
                            task_queue.put_nowait((child_url, depth + 1))
                        except Exception:
                            pass

            task_queue.task_done()

    except asyncio.CancelledError:
        _log("Loop execution cancelled.")
    except Exception as exc:
        _log(f"ERROR: Uncaught loop engine exception: {exc}")
    finally:
        await crawler.stop()
        _log("Worker process closed.")

def run_worker_process(
    instance_id: int,
    worker_id: int,
    task_queue: Any,
    result_list: Any,
    visited_map: Any,
    visited_lock: Any,
    max_depth: int,
    headless: bool,
    webhook_url: str,
) -> None:
    """Worker process launcher."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        asyncio.run(
            async_process_loop(
                instance_id=instance_id,
                worker_id=worker_id,
                task_queue=task_queue,
                result_list=result_list,
                visited_map=visited_map,
                visited_lock=visited_lock,
                max_depth=max_depth,
                headless=headless,
                webhook_url=webhook_url,
            )
        )
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print(f"FATAL worker process engine exception: {exc}", flush=True)

def _generate_report(
    target_url: str,
    results: List[Dict[str, Any]],
    output_path: str = REPORT_FILENAME,
    total_pages: Optional[int] = None,
) -> str:
    """Compile intercept records into grouped breakdowns."""
    hostname = urlparse(target_url).hostname or target_url
    grouped = defaultdict(list)
    seen_fps = set()

    for ep in results:
        fp = f"{ep['method']}|{ep['url']}"
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        grouped[ep["parent_page"]].append(ep)

    total_pages_count = total_pages if total_pages is not None else len(grouped)
    SEP_HEAVY = "=" * 70
    SEP_LIGHT = "-" * 70

    lines = [
        "",
        SEP_HEAVY,
        "             AUTOMATED DISTRIBUTED API HARVESTER REPORT",
        f"Target Origin Hostname: {hostname}",
        f"Total Isolated Pages Analyzed: {total_pages_count}",
        SEP_HEAVY,
        "",
    ]

    for page_url in sorted(grouped.keys()):
        endpoints = grouped[page_url]
        lines.append(f"[PAGE INTERFACE ROUTE]: {page_url}")
        lines.append(SEP_LIGHT)

        for ep in endpoints:
            method_label = ep["method"]
            lines.append(f"  -> [{method_label}] {ep['url']}")
            lines.append(f"     Status Code Verification: {ep['status_code']}")

            auth_line = f"True ({ep['auth_description']})" if ep["requires_auth"] else "False"
            lines.append(f"     Requires Dynamic Auth Headers: {auth_line}")

            if ep.get("query_params"):
                lines.append(f"     Extracted Query Parameters: {ep['query_params']}")

            if ep.get("payload_keys"):
                lines.append(f"     Intercepted Payload Properties: {ep['payload_keys']}")

            lines.append("")

        lines.append(SEP_HEAVY)
        lines.append("")

    report_body = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(report_body)

    return os.path.abspath(output_path)

class DistributedApiHarvester:
    """Multiprocessing master orchestration controller."""

    def __init__(
        self,
        target_url: str,
        instance_count: int = 3,
        max_depth: int = 2,
        headless: bool = True,
        webhook_url: str = "",
    ) -> None:
        self.target_url = target_url.rstrip("/")
        self.instance_count = instance_count
        self.max_depth = max_depth
        self.headless = headless
        self.webhook_url = webhook_url or WEBHOOK_URL

        self._report_path = ""
        self._endpoints_found = 0
        self._pages_analysed = 0
        self._elapsed_seconds = 0.0

    def _log(self, msg: str) -> None:
        line = f"[Instance-0][Worker-0] [MASTER] {msg}"
        print(line, flush=True)
        logger.info(line)

    def start_harvest_cycle(self) -> str:
        """Launch and manage isolated sub-processes."""
        self._log(f"Starting harvest → {self.target_url}")

        manager = multiprocessing.Manager()
        task_queue = manager.Queue()
        result_list = manager.list()
        visited_map = manager.dict()
        visited_lock = manager.Lock()

        # Seed root URL
        task_queue.put((self.target_url, 0))
        self._log("Root URL seeded.")

        processes: List[multiprocessing.Process] = []

        def _shutdown(signum: int, frame: Any) -> None:
            self._log("SIGINT received — terminating processes…")
            for p in processes:
                if p.is_alive():
                    p.terminate()
            _generate_report(self.target_url, list(result_list), total_pages=len(visited_map))
            sys.exit(0)

        # Thread safety guard for signal registration
        import threading
        if threading.current_thread() is threading.main_thread():
            try:
                signal.signal(signal.SIGINT, _shutdown)
            except ValueError:
                pass

        for i in range(self.instance_count):
            instance_id = i + 1
            p = multiprocessing.Process(
                target=run_worker_process,
                name=f"Instance-{instance_id}",
                args=(
                    instance_id,
                    1,
                    task_queue,
                    result_list,
                    visited_map,
                    visited_lock,
                    self.max_depth,
                    self.headless,
                    self.webhook_url,
                ),
            )
            processes.append(p)

        start_time = time.monotonic()

        for p in processes:
            p.start()
            self._log(f"Spawned {p.name} (PID {p.pid})")

        while processes:
            for p in processes[:]:
                p.join(timeout=2)
                if not p.is_alive():
                    processes.remove(p)

        self._elapsed_seconds = time.monotonic() - start_time
        all_results = list(result_list)
        self._endpoints_found = len(all_results)
        self._pages_analysed = len(visited_map)

        self._log(f"Crawl completed. Found {self._endpoints_found} endpoints across {self._pages_analysed} pages.")

        self._report_path = _generate_report(
            target_url=self.target_url,
            results=all_results,
            total_pages=self._pages_analysed,
        )
        manager.shutdown()
        return self._report_path

    @property
    def report_path(self) -> str:
        return self._report_path

    @property
    def endpoints_found(self) -> int:
        return self._endpoints_found

    @property
    def pages_analysed(self) -> int:
        return self._pages_analysed

    @property
    def elapsed_seconds(self) -> float:
        return self._elapsed_seconds
