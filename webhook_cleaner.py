"""
webhook_cleaner.py
══════════════════════════════════════════════════════════════════════════════
Data Normalisation, Classification & Discord Dispatch Utility
──────────────────────────────────────────────────────────────────────────────
Provides `WebhookCleaner` — a stateless utility class responsible for:
  1. Sanitising raw intercept payloads to fit Discord embed field limits.
  2. Classifying each intercept into one of four threat-intel categories.
  3. Dispatching richly-formatted Discord embeds via aiohttp (non-blocking).

Classification Priority Order (first match wins):
  CLASS 1 (Blue / 🔌)  →  STREAMING DATA / WEBSOCKETS (wss://, ws:// or live feeds)
  CLASS 2 (Yellow / 🪣) →  EXPOSED CLOUD STORAGE (S3, Google Cloud, Azure blobs)
  CLASS 3 (Red / 🔒)   →  SECURED AUTHENTICATED API (Auth / JWT in headers)
  CLASS 4 (Green / ⚙️)  →  STANDARD REST ENDPOINT (Fallback REST API calls)
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
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# ── Per-process webhook rate-limiter ─────────────────────────────────────────
# Limits to 2 concurrent webhook POST requests per worker process.
# Initialized lazily so it always binds to the correct running event loop.
_WEBHOOK_SEM: Optional[asyncio.Semaphore] = None
_MAX_WEBHOOK_RETRIES: int = 2

def _get_webhook_sem() -> asyncio.Semaphore:
    """Return (or create) the module-level semaphore bound to the running loop."""
    global _WEBHOOK_SEM
    if _WEBHOOK_SEM is None:
        _WEBHOOK_SEM = asyncio.Semaphore(2)
    return _WEBHOOK_SEM

# Discord limits
_EMBED_FIELD_MAX: int = 1024
_EMBED_TITLE_MAX: int = 256
_TRUNCATION_SUFFIX: str = "… [truncated]"

# Classification Keywords
_STREAM_KEYWORDS: List[str] = [
    "ticker", "feed", "calendar", "market-data", "marketdata",
    "stream", "live", "realtime", "real-time", "subscribe",
    "socket", "push", "events", "sse", "ws", "wss",
]
_STREAM_KEYWORD_RE: re.Pattern[str] = re.compile(
    "|".join(re.escape(k) for k in _STREAM_KEYWORDS),
    re.IGNORECASE,
)

_CLOUD_STORAGE_RE: re.Pattern[str] = re.compile(
    r"(\.s3\.amazonaws\.com"
    r"|storage\.googleapis\.com"
    r"|blob\.core\.windows\.net"
    r"|\.r2\.cloudflarestorage\.com"
    r"|\.digitaloceanspaces\.com"
    r"|\.backblazeb2\.com"
    r"|\.wasabisys\.com"
    r"|cloudfront\.net)",
    re.IGNORECASE,
)

_AUTH_HEADER_KEYS: frozenset[str] = frozenset({
    "authorization", "x-api-key", "jwt", "token",
    "x-auth-token", "x-access-token", "x-token",
})

class InterceptClass:
    """Immutable payload classification record."""
    __slots__ = ("label", "emoji", "color", "rank")

    def __init__(self, label: str, emoji: str, color: int, rank: int) -> None:
        self.label: str = label
        self.emoji: str = emoji
        self.color: int = color
        self.rank: int = rank

_CLASS_1 = InterceptClass("STREAMING DATA PIPELINE", "🔌", 3447003, 1)  # Blue
_CLASS_2 = InterceptClass("EXPOSED STORAGE ASSET", "🪣", 16776960, 2)   # Yellow
_CLASS_3 = InterceptClass("SECURED AUTHENTICATED API", "🔒", 15158332, 3) # Red
_CLASS_4 = InterceptClass("STANDARD REST ENDPOINT", "⚙️", 3066993, 4)   # Green

class WebhookCleaner:
    """Stateless utility class for formatting and dispatching Discord webhooks."""

    @staticmethod
    def truncate(value: Any, max_len: int = _EMBED_FIELD_MAX) -> str:
        """Convert value to string and truncate to max_len safely."""
        text: str = str(value) if not isinstance(value, str) else value
        if len(text) <= max_len:
            return text
        cut: int = max_len - len(_TRUNCATION_SUFFIX)
        return text[:cut] + _TRUNCATION_SUFFIX

    @staticmethod
    def truncate_title(value: str) -> str:
        """Truncate to Discord's embed title limit."""
        if len(value) <= _EMBED_TITLE_MAX:
            return value
        cut: int = _EMBED_TITLE_MAX - len(_TRUNCATION_SUFFIX)
        return value[:cut] + _TRUNCATION_SUFFIX

    @staticmethod
    def classify(
        url: str,
        method: str,
        req_headers: Dict[str, str],
        content_type: str,
    ) -> InterceptClass:
        """Classify the endpoint into one of the four taxonomics classes."""
        url_lower: str = url.lower()
        method_upper: str = method.upper()

        # Class 1: WebSocket / Streaming
        if (
            url_lower.startswith(("ws://", "wss://"))
            or method_upper in ("WS", "WSS")
            or _STREAM_KEYWORD_RE.search(url_lower)
        ):
            return _CLASS_1

        # Class 2: Cloud Storage
        if _CLOUD_STORAGE_RE.search(url_lower):
            return _CLASS_2

        # Class 3: Authenticated/Secured
        norm_headers: Dict[str, str] = {k.lower(): v for k, v in req_headers.items()}
        for key in _AUTH_HEADER_KEYS:
            if norm_headers.get(key, ""):
                return _CLASS_3

        # Class 4: Standard REST Endpoint
        return _CLASS_4

    @staticmethod
    def describe_auth(req_headers: Dict[str, str]) -> tuple[bool, str]:
        """Describe authentication schema from headers safely."""
        norm: Dict[str, str] = {k.lower(): v for k, v in req_headers.items()}
        auth_val: str = norm.get("authorization", "")
        if auth_val:
            scheme: str = auth_val.split(" ")[0].lower()
            if scheme == "bearer":
                return True, "Bearer JWT Token"
            if scheme == "basic":
                return True, "Basic Auth"
            return True, f"Scheme: {scheme}"

        if norm.get("x-api-key", ""):
            return True, "API Key (x-api-key)"
        if norm.get("x-auth-token", ""):
            return True, "Token (x-auth-token)"
        for key in ("jwt", "token", "x-token", "x-access-token"):
            if norm.get(key, ""):
                return True, f"Custom header: {key}"

        return False, ""

    @classmethod
    def _build_embed(
        cls,
        intercept_class: InterceptClass,
        url: str,
        method: str,
        status_code: int,
        parent_page: str,
        requires_auth: bool,
        auth_desc: str,
        query_params: List[str],
        payload_keys: List[str],
        content_type: str,
        instance_id: int,
        worker_id: int,
    ) -> Dict[str, Any]:
        """Construct a Discord-compliant embed dictionary."""
        auth_display: str = f"✅ True — {auth_desc}" if requires_auth else "⬜ False"
        qp_display: str = cls.truncate(str(query_params) if query_params else "None")
        pk_display: str = cls.truncate(str(payload_keys) if payload_keys else "N/A")
        ct_display: str = cls.truncate(content_type or "unknown")
        ts: str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        fields: List[Dict[str, Any]] = [
            {"name": "📌 Parent Page",          "value": cls.truncate(parent_page),  "inline": False},
            {"name": "🌐 Endpoint URL",          "value": cls.truncate(url),          "inline": False},
            {"name": "⚡ HTTP Method",           "value": f"`{method}`",              "inline": True},
            {"name": "📊 Status Code",           "value": f"`{status_code}`",         "inline": True},
            {"name": "🔐 Auth Required",         "value": auth_display,               "inline": True},
            {"name": "🗂️ Content-Type",          "value": f"`{ct_display}`",          "inline": True},
            {"name": "🔎 Query Parameters",      "value": qp_display,                 "inline": False},
        ]

        if payload_keys:
            fields.append({
                "name":   "📦 Payload Schema Keys",
                "value":  pk_display,
                "inline": False,
            })

        return {
            "title":       cls.truncate_title(
                f"{intercept_class.emoji} CLASS {intercept_class.rank}: "
                f"[{intercept_class.label}]"
            ),
            "description": cls.truncate(
                f"Intercepted by `[Instance-{instance_id}][Worker-{worker_id}]`\n⏱️ `{ts}`"
            ),
            "color":       intercept_class.color,
            "fields":      fields,
            "footer": {
                "text": "Distributed API Harvesting Engine • Real-Time Intel"
            },
        }

    @classmethod
    async def dispatch_scrubbed_alert(
        cls,
        webhook_url: str,
        url: str,
        method: str,
        status_code: int,
        parent_page: str,
        req_headers: Dict[str, str],
        content_type: str,
        query_params: List[str],
        payload_keys: List[str],
        instance_id: int = 0,
        worker_id: int = 0,
    ) -> None:
        """Classify, format, and dispatch embed warning card to a Discord webhook.

        Rate-limiting strategy:
          - A per-process asyncio.Semaphore(2) caps concurrent POST calls.
          - On HTTP 429, the response JSON's retry_after value is respected
            and the request is retried once before being silently dropped.
        """
        if not webhook_url or "YOUR_WEBHOOK_URL_PLACEHOLDER" in webhook_url:
            return

        try:
            intercept_class = cls.classify(url, method, req_headers, content_type)
            requires_auth, auth_desc = cls.describe_auth(req_headers)

            embed = cls._build_embed(
                intercept_class=intercept_class,
                url=url,
                method=method,
                status_code=status_code,
                parent_page=parent_page,
                requires_auth=requires_auth,
                auth_desc=auth_desc,
                query_params=query_params,
                payload_keys=payload_keys,
                content_type=content_type,
                instance_id=instance_id,
                worker_id=worker_id,
            )

            payload: Dict[str, Any] = {
                "username":   "API Harvester",
                "avatar_url": "https://cdn-icons-png.flaticon.com/512/2534/2534230.png",
                "embeds":     [embed],
            }

            sem = _get_webhook_sem()
            async with sem:
                async with aiohttp.ClientSession() as session:
                    for attempt in range(_MAX_WEBHOOK_RETRIES):
                        try:
                            async with session.post(
                                webhook_url,
                                json=payload,
                                timeout=aiohttp.ClientTimeout(total=12),
                            ) as resp:
                                if resp.status == 429:
                                    # Parse Discord's retry_after and sleep before retrying
                                    try:
                                        data = await resp.json(content_type=None)
                                        retry_after: float = float(data.get("retry_after", 1.5))
                                    except Exception:
                                        retry_after = 1.5
                                    logger.debug(
                                        "Webhook 429 — sleeping %.2fs before retry %d/%d",
                                        retry_after, attempt + 1, _MAX_WEBHOOK_RETRIES,
                                    )
                                    await asyncio.sleep(retry_after + 0.1)
                                    continue  # retry
                                elif resp.status not in (200, 204):
                                    body: str = await resp.text()
                                    logger.warning(
                                        "Webhook alert returned status %d: %s",
                                        resp.status, body[:200],
                                    )
                                break  # success or non-retryable error
                        except aiohttp.ClientError as ce:
                            logger.debug("Webhook client error (attempt %d): %s", attempt + 1, ce)
                            if attempt < _MAX_WEBHOOK_RETRIES - 1:
                                await asyncio.sleep(1.0)
                            continue

        except Exception as exc:
            logger.error("Failed to dispatch real-time alert webhook: %s", exc)

    @classmethod
    async def dispatch_summary_card(
        cls,
        webhook_url: str,
        target_url: str,
        pages_analysed: int,
        endpoints_found: int,
        elapsed_seconds: float,
        instance_count: int,
    ) -> None:
        """Send a formatted wrap-up card summarising crawl parameters."""
        if not webhook_url or "YOUR_WEBHOOK_URL_PLACEHOLDER" in webhook_url:
            return

        embed: Dict[str, Any] = {
            "title":       "✅ Harvest Complete — Summary Report",
            "description": cls.truncate(
                f"**Target:** `{target_url}`\n"
                f"**Processes Used:** `{instance_count}`\n"
                f"**Duration:** `{elapsed_seconds:.1f}s`"
            ),
            "color": 3066993,
            "fields": [
                {"name": "📄 Pages Analysed",    "value": str(pages_analysed),  "inline": True},
                {"name": "🔗 Endpoints Found",   "value": str(endpoints_found), "inline": True},
            ],
            "footer": {"text": "Distributed API Harvesting Engine"},
        }

        payload: Dict[str, Any] = {
            "username": "API Harvester",
            "embeds":   [embed],
        }

        try:
            async with aiohttp.ClientSession() as session:
                await session.post(
                    webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                )
        except Exception as exc:
            logger.error("Failed to dispatch summary card webhook: %s", exc)
