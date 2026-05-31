# 🕸️ Distributed API Harvesting Engine

A production-ready, multi-process Python framework that maps target infrastructure, intercepts live network handshakes, detects exposed cloud assets, and isolates active streaming data channels — all controlled via a Discord bot.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [File Structure](#-file-structure)
- [Setup](#-setup)
- [Configuration](#-configuration)
- [Discord Commands](#-discord-commands)
- [Classification System](#-classification-system)
- [Output Report](#-output-report)
- [Technical Notes](#-technical-notes)
- [Troubleshooting](#-troubleshooting)

---

## ✨ Features

| Feature | Details |
|---|---|
| **Stealth Browser** | Playwright Chromium with full fingerprint neutralisation (webdriver flag, plugins, WebGL, canvas noise, Chrome runtime) |
| **Network Interception** | Captures every XHR, Fetch, and WebSocket frame in real-time |
| **Smart Filtering** | Auto-drops telemetry (Google Analytics, Sentry, Hotjar, etc.) and static assets |
| **Anti-bot Evasion** | Randomised 1–5s politeness delay between page visits to bypass WAFs |
| **4-Tier Classification** | Streaming pipelines, exposed cloud storage, authenticated APIs, standard REST |
| **Multiprocessing** | N isolated OS processes each running an independent async event loop |
| **Discord Webhook Alerts** | Real-time colour-coded embeds streamed as endpoints are discovered |
| **Rate-limit Resilient** | Per-process semaphore + automatic `retry_after` backoff on Discord 429s |
| **Discord Bot Control** | `!harvest` / `!stop` / `!status` commands with per-channel process tracking |
| **Full Process Kill** | `!stop` uses `psutil` to recursively terminate all grandchild browser workers |
| **Report Export** | Structured `api_breakdown.txt` uploaded to Discord on completion |

---

## 🏗️ Architecture

```
Discord User
     │
     │  !harvest <url>
     ▼
┌─────────────────────────────────────┐
│  bot.py  (Discord Bot — main thread) │
│  active_scans: Dict[channel_id, Process] │
└────────────────┬────────────────────┘
                 │ multiprocessing.Process
                 ▼
┌─────────────────────────────────────────────┐
│  distributed_api_harvester.py               │
│  DistributedApiHarvester.start_harvest_cycle│
│  ┌──────────────────────────────────────┐   │
│  │  Manager Queue / List / Dict / Lock  │   │
│  └──────────────────────────────────────┘   │
│        │           │           │            │
│  Process-1   Process-2   Process-3  ...     │
└──────────────────────────────────────────────┘
        │
        ▼  asyncio.run()
┌──────────────────────────────────────┐
│  async_process_loop()                │
│  ApiDiscoveryCrawler.crawl_page()    │
│  ├── stealth.py  (JS evasion layer)  │
│  └── webhook_cleaner.py  (alerts)    │
└──────────────────────────────────────┘
        │
        ▼
  Discord Webhook  (real-time embeds)
```

**Data flow:**  
`page response` → intercept → classify → build embed → semaphore → POST to webhook  
`child links` → normalize → dedup lock → queue → next worker picks up

---

## 📁 File Structure

```
Scraper/
├── .env                        # Runtime secrets (never commit)
├── .env.example                # Safe placeholder template
├── .gitignore                  # Excludes .env, __pycache__, reports
├── requirements.txt            # All dependencies
│
├── bot.py                      # Discord bot — command listener & process orchestrator
├── distributed_api_harvester.py # Multiprocessing supervisor & report generator
├── api_discovery_crawler.py    # Playwright async crawler & network sniffer
├── stealth.py                  # Browser fingerprint neutralisation layer
├── webhook_cleaner.py          # Payload sanitiser, classifier & Discord dispatcher
│
└── api_breakdown.txt           # Generated report (auto-uploaded to Discord)
```

---

## ⚙️ Setup

### 1. Prerequisites

- Python **3.10+**
- A Discord server where you have **Manage Webhooks** and **Bot** permissions

### 2. Clone / Download

```bash
git clone https://github.com/exawill/Python-API-Scraper/
cd Python-API-Scraper
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
playwright install chromium
```

### 4. Create a Discord Bot

1. Go to [discord.com/developers/applications](https://discord.com/developers/applications)
2. **New Application** → give it a name
3. **Bot** tab → **Add Bot** → copy the **Token**
4. Under **Privileged Gateway Intents**, enable **Message Content Intent**
5. **OAuth2 → URL Generator**: select `bot` scope + `Send Messages`, `Read Messages/View Channels`, `Attach Files` permissions
6. Use the generated URL to invite the bot to your server

### 5. Create a Discord Webhook

1. In your Discord server: **Server Settings → Integrations → Webhooks → New Webhook**
2. Choose the channel where you want real-time intercept alerts
3. Copy the **Webhook URL**

### 6. Configure `.env`

```env
DISCORD_BOT_TOKEN=your_bot_token_here
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

### 7. Run

```bash
python bot.py
```

You should see:

```
  Distributed API Harvesting Engine — Discord Bot
  Token  : ********************xxxxxx
  Webhook: configured

  ✓  Bot online: YourBot#1234
  ✓  Prefix: !
  ✓  Commands: !harvest, !stop, !status, !help
```

---

## 🎮 Discord Commands

| Command | Description | Example |
|---|---|---|
| `!harvest <url>` | Start a harvest with default settings (3 processes, depth 2) | `!harvest https://example.com` |
| `!harvest <url> <instances> <depth>` | Custom process count (1–10) and crawl depth (0–5) | `!harvest https://example.com 2 3` |
| `!stop` | Force-kill the active harvest in this channel (kills all browser workers) | `!stop` |
| `!status` | Check whether the engine is idle or running | `!status` |
| `!help` | Display all available commands | `!help` |

> **Note:** Each Discord channel tracks its own harvest independently. You can run harvests in multiple channels simultaneously.

---

## 🏷️ Classification System

Every intercepted endpoint is classified into one of four tiers (first match wins):

| Class | Colour | Emoji | Trigger Condition |
|---|---|---|---|
| **CLASS 1** — Streaming Data Pipeline | 🔵 Blue | 🔌 | `wss://`, `ws://`, or URL contains: `stream`, `feed`, `live`, `realtime`, `socket`, `sse`, `ticker` |
| **CLASS 2** — Exposed Storage Asset | 🟡 Yellow | 🪣 | URL matches: `.s3.amazonaws.com`, `storage.googleapis.com`, `blob.core.windows.net`, Cloudflare R2, DigitalOcean Spaces, Backblaze B2 |
| **CLASS 3** — Secured Authenticated API | 🔴 Red | 🔒 | Request headers contain: `Authorization`, `x-api-key`, `jwt`, `x-auth-token`, `x-access-token` |
| **CLASS 4** — Standard REST Endpoint | 🟢 Green | ⚙️ | Fallback: any XHR/Fetch not matching classes 1–3 |

---

## 📄 Output Report

When a harvest completes, `api_breakdown.txt` is automatically uploaded to your Discord channel. Format:

```
======================================================================
             AUTOMATED DISTRIBUTED API HARVESTER REPORT
Target Origin Hostname: example.com
Total Isolated Pages Analyzed: 12
======================================================================

[PAGE INTERFACE ROUTE]: https://example.com/dashboard
----------------------------------------------------------------------
  -> [GET] https://api.example.com/v2/user/profile
     Status Code Verification: 200
     Requires Dynamic Auth Headers: True (Bearer JWT Token)
     Extracted Query Parameters: ['include', 'fields']

  -> [POST] https://api.example.com/v2/orders
     Status Code Verification: 201
     Requires Dynamic Auth Headers: True (Bearer JWT Token)
     Intercepted Payload Properties: ['product_id', 'quantity', 'address']
======================================================================
```

---

## 🔧 Technical Notes

### Concurrency Model

- **Supervisor process** (`_run_harvester_process`) is spawned by the bot — completely isolated from the Discord event loop.
- **Worker processes** (`Instance-1`, `Instance-2`, ...) are spawned by the supervisor — each runs a full Playwright Chromium instance.
- **Shared state** between workers uses `multiprocessing.Manager` primitives: `Queue`, `list`, `dict`, `Lock`.
- **Visited deduplication** is atomic via `Manager().Lock()` — prevents two workers crawling the same URL.

### Safety Caps

| Limit | Value | Reason |
|---|---|---|
| Max pages per run | 50 | Hard cap in `visited_map` to prevent infinite crawl loops |
| Politeness delay | 1.0 – 5.0s | Random uniform delay to bypass WAF rate limits |
| Max crawl depth | 0 – 5 (default: 2) | Prevents exponential link explosion |
| Max process count | 1 – 10 (default: 3) | Capped to prevent resource exhaustion |
| Worker idle limit | 5 missed polls | Worker exits after 5 consecutive empty queue polls |

### Webhook Rate Limiting

- Each worker process holds an `asyncio.Semaphore(2)` — max 2 concurrent POSTs per process
- On **HTTP 429**: automatically sleeps for Discord's `retry_after` value + 100ms buffer, then retries once
- Repeated 429s are silently dropped (logged at DEBUG level only)

---

## 🐛 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `playwright._impl._errors.Error: Browser closed` on first run | One-time Chromium init race | Re-run `!harvest` — resolves itself |
| `signal only works in main thread` | Running harvester in a thread instead of a process | Already fixed — harvester runs in `multiprocessing.Process` |
| `UnicodeEncodeError` on Windows console | Windows CP1252 default encoding | Already fixed — all files force `utf-8` on `sys.stdout/stderr` |
| Webhook embeds not appearing | Webhook URL not set in `.env` | Verify `DISCORD_WEBHOOK_URL` is configured correctly |
| `!stop` didn't kill browser windows | `psutil` not installed | Run `pip install psutil` or `pip install -r requirements.txt` |
| All pages return 403 | Target site blocks headless browsers | The stealth layer reduces detection; some sites require proxy rotation |
| Bot won't start — `LoginFailure` | Invalid bot token | Regenerate token in Discord Developer Portal |

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `playwright` | Headless Chromium browser automation & network interception |
| `beautifulsoup4` | HTML link extraction from page content |
| `lxml` | Fast HTML parser backend for BeautifulSoup |
| `aiohttp` | Async HTTP client for Discord webhook dispatch |
| `discord.py` | Discord bot framework |
| `python-dotenv` | Secure `.env` file loading |
| `psutil` | Cross-platform process tree management for `!stop` |

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security research, penetration testing, and educational purposes only**. Only use it against systems you own or have explicit written permission to test. Unauthorized scanning of third-party infrastructure may violate the Computer Fraud and Abuse Act (CFAA), GDPR, or equivalent laws in your jurisdiction.
