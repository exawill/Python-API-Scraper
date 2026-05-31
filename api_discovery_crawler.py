"""
api_discovery_crawler.py
══════════════════════════════════════════════════════════════════════════════
Async Network Sniffer Engine
──────────────────────────────────────────────────────────────────────────────
Drives a single Playwright Chromium instance per OS subprocess.
Intercepts background traffic, classifies endpoints in real-time,
dispatches Discord webhook alerts without stalling page rendering,
and harvests internal links for the distributed task queue.

Imports:
  stealth.py         → apply_stealth_vitals()
  webhook_cleaner.py → WebhookCleaner
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
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup
from dotenv import load_dotenv
from playwright.async_api import (
    async_playwright,
    BrowserContext,
    Page,
    Response,
    WebSocket,
    Error as PlaywrightError,
)

from stealth import apply_stealth_vitals
from webhook_cleaner import WebhookCleaner

load_dotenv()
logger = logging.getLogger(__name__)

# Config constants
PAGE_TIMEOUT_MS: int = 30_000
IDLE_WAIT_MS: int = 3_000
MAX_RETRIES: int = 2

USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

# Extension filters
_SKIP_EXT: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".js", ".mjs", ".ts",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z", ".mp3", ".mp4", ".avi",
    ".mov", ".webm", ".wav", ".map", ".wasm"
}

# Telemetry domains to immediately drop
_NOISE_DOMAINS: Set[str] = {
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "facebook.net", "hotjar.com", "mixpanel.com", "segment.io",
    "amplitude.com", "sentry.io", "datadoghq.com", "bugsnag.com"
}

_API_PATH_RE: re.Pattern[str] = re.compile(
    r"(/api/|/v\d+/|/graphql|/rest/|/service/|/endpoint)",
    re.IGNORECASE,
)

_JS_ROUTE_RE: List[re.Pattern[str]] = [
    re.compile(
        r"""(?:fetch|axios(?:\.get|\.post|\.put|\.delete|\.patch)?)\s*\(\s*['"`]([^'"`\s]{4,})['"`]""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""(?:window\.location|location\.href|router\.push|navigate|history\.pushState)\s*[=(,]\s*['"]([^'"#?]{3,})['"]""",
        re.IGNORECASE,
    ),
]

@dataclass
class ApiEndpoint:
    """Dataclass holding details of a discovered API endpoint."""
    parent_page: str
    url: str
    method: str
    status_code: int
    content_type: str
    requires_auth: bool = False
    auth_description: str = ""
    query_params: List[str] = field(default_factory=list)
    payload_keys: List[str] = field(default_factory=list)
    signal_type: str = "XHR/Fetch"

    @property
    def dedup_key(self) -> str:
        raw: str = f"{self.method}|{self.url}"
        return hashlib.sha256(raw.encode()).hexdigest()[:20]

@dataclass
class CrawlResult:
    """Aggregated output of a single page crawl execution."""
    page_url: str
    endpoints: List[ApiEndpoint] = field(default_factory=list)
    child_links: List[str] = field(default_factory=list)
    load_ms: float = 0.0
    status_code: int = 0
    error: Optional[str] = None

def _is_noise(url: str) -> bool:
    try:
        hostname: str = urlparse(url).hostname or ""
    except Exception:
        return True
    parts = hostname.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in _NOISE_DOMAINS:
            return True
    return False

def _is_static_asset(url: str) -> bool:
    try:
        return any(urlparse(url).path.lower().endswith(ext) for ext in _SKIP_EXT)
    except Exception:
        return True

def _looks_like_api(url: str, content_type: str, resource_type: str) -> bool:
    ct: str = content_type.lower()
    if "json" in ct or "xml" in ct:
        return True
    if resource_type in ("xhr", "fetch"):
        return True
    if _API_PATH_RE.search(url):
        return True
    return False

def _extract_payload_keys(post_data: Optional[str]) -> List[str]:
    """Safely decode JSON payload schemas."""
    if not post_data:
        return []
    try:
        obj: Any = json.loads(post_data)
        if isinstance(obj, dict):
            return list(obj.keys())[:30]
        if isinstance(obj, list) and obj and isinstance(obj[0], dict):
            return list(obj[0].keys())[:30]
    except Exception:
        pass
    return []

def _extract_links(html: str, current_url: str, base_domain: str) -> List[str]:
    """Extract and normalise inner domain links from anchor elements and inline routes."""
    soup = BeautifulSoup(html, "html.parser")
    seen: Set[str] = set()
    links: List[str] = []

    def _add(raw: str) -> None:
        if not raw:
            return
        raw = raw.split("#")[0].strip()
        if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "data:")):
            return
        absolute: str = urljoin(current_url, raw)
        normalised: str = absolute.rstrip("/").strip()
        parsed = urlparse(normalised)
        if not parsed.scheme.startswith("http"):
            return
        hostname: str = parsed.hostname or ""
        if not (hostname == base_domain or hostname.endswith(f".{base_domain}")):
            return
        if any(parsed.path.lower().endswith(ext) for ext in _SKIP_EXT):
            return
        if normalised not in seen:
            seen.add(normalised)
            links.append(normalised)

    for tag in soup.find_all("a", href=True):
        _add(tag["href"])
    for tag in soup.find_all("form", action=True):
        _add(tag["action"])
    for tag in soup.find_all(True):
        for attr in ("data-href", "data-url", "data-action", "data-link", "data-path"):
            val = tag.get(attr)
            if val:
                _add(str(val))
    for pattern in _JS_ROUTE_RE:
        for match in pattern.finditer(html):
            _add(match.group(1))

    return links

class ApiDiscoveryCrawler:
    """Plays target pages using Playwright and monitors background traffic networks."""

    def __init__(
        self,
        instance_id: int = 0,
        worker_id: int = 0,
        headless: bool = True,
        webhook_url: str = "",
    ) -> None:
        self.instance_id: int = instance_id
        self.worker_id: int = worker_id
        self.headless: bool = headless
        self.webhook_url: str = webhook_url
        self._prefix: str = f"[Instance-{instance_id}][Worker-{worker_id}]"

        self._playwright: Any = None
        self._browser: Any = None
        self._context: Optional[BrowserContext] = None

    def _log(self, msg: str) -> None:
        line: str = f"{self._prefix} {msg}"
        print(line, flush=True)
        logger.info(line)

    async def start(self) -> None:
        """Startup Playwright loop engine context."""
        self._log("Launching Chromium browser context…")
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=self.headless,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
                "--disable-extensions",
                "--disable-dev-shm-usage",
                "--no-first-run",
                "--no-default-browser-check",
            ],
            ignore_default_args=["--enable-automation"],
        )
        self._context = await self._browser.new_context(
            user_agent=USER_AGENT,
            viewport={"width": 1280, "height": 800},
            java_script_enabled=True,
            ignore_https_errors=True,
        )
        # Context-level tracker blocker
        await self._context.route(
            re.compile(r"(google-analytics\.com|googletagmanager\.com|doubleclick\.net|clarity\.ms|sentry\.io)"),
            lambda route: route.abort(),
        )
        self._log("Browser context initialised.")

    async def stop(self) -> None:
        """Close browser resources cleanly."""
        try:
            if self._context:
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
            self._log("Browser resources cleanly closed.")
        except Exception as exc:
            self._log(f"Browser closure exception: {exc}")

    async def crawl_page(
        self,
        url: str,
        base_domain: str,
        depth: int = 0,
        max_depth: int = 2,
    ) -> CrawlResult:
        """Crawl the given page and capture network responses."""
        result = CrawlResult(page_url=url)
        if not self._context:
            result.error = "Browser context not initialised."
            return result

        page: Page = await self._context.new_page()
        # Apply browser evasion layer
        await apply_stealth_vitals(page)

        captured: List[ApiEndpoint] = []

        # WS Interceptor
        def _on_websocket(ws: WebSocket) -> None:
            ws_url: str = ws.url
            self._log(f"WebSocket detected: {ws_url[:80]}")
            
            def _on_frame(payload: Any, direction: str) -> None:
                ep = ApiEndpoint(
                    parent_page=url,
                    url=ws_url,
                    method="WSS" if ws_url.startswith("wss://") else "WS",
                    status_code=101,
                    content_type="application/octet-stream",
                    signal_type="WebSocket",
                )
                if not any(e.url == ws_url and e.signal_type == "WebSocket" for e in captured):
                    captured.append(ep)
                    asyncio.create_task(
                        WebhookCleaner.dispatch_scrubbed_alert(
                            webhook_url=self.webhook_url,
                            url=ws_url,
                            method=ep.method,
                            status_code=101,
                            parent_page=url,
                            req_headers={},
                            content_type="application/octet-stream",
                            query_params=list(parse_qs(urlparse(ws_url).query).keys()),
                            payload_keys=[],
                            instance_id=self.instance_id,
                            worker_id=self.worker_id,
                        )
                    )

            ws.on("framesent", lambda p: _on_frame(p, "send"))
            ws.on("framereceived", lambda p: _on_frame(p, "receive"))

        page.on("websocket", _on_websocket)

        # Network interceptor
        async def _on_response(response: Response) -> None:
            try:
                resp_url: str = response.url
                req = response.request
                res_type: str = req.resource_type
                content_type: str = response.headers.get("content-type", "")
                status_code: int = response.status

                if _is_noise(resp_url) or _is_static_asset(resp_url):
                    return
                if not _looks_like_api(resp_url, content_type, res_type):
                    return

                method: str = req.method
                req_headers: Dict[str, str] = {k.lower(): v for k, v in req.headers.items()}
                requires_auth, auth_desc = WebhookCleaner.describe_auth(req_headers)

                # Extract query parameters
                parsed_query = urlparse(resp_url).query
                q_params = list(parse_qs(parsed_query).keys())

                # POST body properties extraction
                payload_keys: List[str] = []
                if method in ("POST", "PUT", "PATCH"):
                    try:
                        post_data = req.post_data
                    except Exception:
                        post_data = None
                    payload_keys = _extract_payload_keys(post_data)

                ep = ApiEndpoint(
                    parent_page=url,
                    url=resp_url,
                    method=method,
                    status_code=status_code,
                    content_type=content_type,
                    requires_auth=requires_auth,
                    auth_description=auth_desc,
                    query_params=q_params,
                    payload_keys=payload_keys,
                    signal_type="XHR/Fetch",
                )
                captured.append(ep)
                self._log(f"Intercepted [{method}] {resp_url[:80]} | status={status_code}")

                # Non-blocking web-hook dispatch
                asyncio.create_task(
                    WebhookCleaner.dispatch_scrubbed_alert(
                        webhook_url=self.webhook_url,
                        url=resp_url,
                        method=method,
                        status_code=status_code,
                        parent_page=url,
                        req_headers=req_headers,
                        content_type=content_type,
                        query_params=q_params,
                        payload_keys=payload_keys,
                        instance_id=self.instance_id,
                        worker_id=self.worker_id,
                    )
                )
            except Exception as e:
                logger.debug("Response interception skipped: %s", e)

        page.on("response", _on_response)

        # Page navigation with robust error catching
        html: str = ""
        http_status: int = 0
        nav_ok: bool = False

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                t0 = time.monotonic()
                resp = await page.goto(url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
                result.load_ms = round((time.monotonic() - t0) * 1000, 2)
                http_status = resp.status if resp else 0

                try:
                    await page.wait_for_load_state("networkidle", timeout=IDLE_WAIT_MS)
                except Exception:
                    pass

                # Simulate scrolling to trigger lazy loads
                for _ in range(3):
                    await page.evaluate("window.scrollBy(0, window.innerHeight * 0.8)")
                    await asyncio.sleep(0.4)
                await page.evaluate("window.scrollTo(0, 0)")

                html = await page.content()
                nav_ok = True
                break
            except PlaywrightError as pe:
                self._log(f"Navigation warning (attempt {attempt}/{MAX_RETRIES}): {pe}")
                await asyncio.sleep(2)
            except Exception as exc:
                result.error = str(exc)
                break

        try:
            page.remove_listener("response", _on_response)
            page.remove_listener("websocket", _on_websocket)
        except Exception:
            pass

        if not nav_ok and not result.error:
            result.error = f"Failed to load page after {MAX_RETRIES} attempts."

        result.endpoints = captured
        result.status_code = http_status

        if depth < max_depth and html and nav_ok:
            result.child_links = _extract_links(html, url, base_domain)

        await page.close()
        return result
