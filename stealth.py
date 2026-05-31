"""
stealth.py
══════════════════════════════════════════════════════════════════════════════
Browser Evasion & Fingerprint Neutralisation Layer
──────────────────────────────────────────────────────────────────────────────
Exports:
    apply_stealth_vitals(page)

Injects a JavaScript init-script block into every new document context
BEFORE any page-level script executes, surgically removing all signals that
identify the browser as an automated Playwright session.

CRITICAL COMMENT POLICY:
  Every annotation inside the injected JavaScript string uses JS double-slash
  (//) syntax exclusively. Python hash (#) characters are intentionally absent
  from within the JS literal to prevent the V8 engine from raising a runtime
  Evaluation SyntaxError when the script is parsed.
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

import logging
from playwright.async_api import Page

logger = logging.getLogger(__name__)

# ── JavaScript Stealth Payload ────────────────────────────────────────────────
# ALL internal annotations use // JavaScript comment syntax ONLY.
_STEALTH_JS: str = r"""
(function () {
    // ── 1. Erase the navigator.webdriver property signature ───────────────────
    Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined,
        configurable: true,
        enumerable: false,
    });

    // ── 2. Spoof navigator.languages to a standard en-US consumer profile ─────
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en'],
        configurable: true,
    });

    // ── 3. Mock a credible plugin list (length === 3 matches stock Chrome) ─────
    Object.defineProperty(navigator, 'plugins', {
        get: () => {
            const plugins = [
                { name: 'Chrome PDF Plugin',    filename: 'internal-pdf-viewer',              description: 'Portable Document Format' },
                { name: 'Chrome PDF Viewer',    filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: ''                        },
                { name: 'Native Client',        filename: 'internal-nacl-plugin',             description: ''                        },
            ];
            // Restore the prototype chain so instanceof PluginArray returns true
            Object.setPrototypeOf(plugins, PluginArray.prototype);
            return plugins;
        },
        configurable: true,
    });

    // ── 4. MimeType array aligned with the plugin list above ─────────────────
    Object.defineProperty(navigator, 'mimeTypes', {
        get: () => {
            const mimes = [{ type: 'application/pdf', suffixes: 'pdf', description: '' }];
            Object.setPrototypeOf(mimes, MimeTypeArray.prototype);
            return mimes;
        },
        configurable: true,
    });

    // ── 5. Inject the window.chrome runtime object (missing in raw headless) ──
    if (!window.chrome || !window.chrome.runtime) {
        window.chrome = {
            app:       { isInstalled: false, InstallState: {}, RunningState: {} },
            runtime:   { id: undefined },
            loadTimes: function () { return {}; },
            csi:       function () { return {}; },
        };
    }

    // ── 6. Permissions API: report notification state as denied, not prompt ───
    const _origPermQuery =
        window.navigator.permissions &&
        window.navigator.permissions.query.bind(window.navigator.permissions);
    if (_origPermQuery) {
        window.navigator.permissions.query = function (params) {
            if (params && params.name === 'notifications') {
                return Promise.resolve({ state: 'denied', onchange: null });
            }
            return _origPermQuery(params);
        };
    }

    // ── 7. WebGL vendor and renderer spoofing (Intel integrated profile) ──────
    const _patchWebGL = function (ContextClass) {
        if (!ContextClass) return;
        const _orig = ContextClass.prototype.getParameter;
        ContextClass.prototype.getParameter = function (param) {
            // UNMASKED_VENDOR_WEBGL   = 37445
            if (param === 37445) return 'Intel Inc.';
            // UNMASKED_RENDERER_WEBGL = 37446
            if (param === 37446) return 'Intel Iris OpenGL Engine';
            return _orig.call(this, param);
        };
    };
    _patchWebGL(window.WebGLRenderingContext);
    _patchWebGL(window.WebGL2RenderingContext);

    // ── 8. Canvas toDataURL pixel noise (defeats canvas hash fingerprinting) ──
    const _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function (type) {
        const ctx = this.getContext && this.getContext('2d');
        if (ctx && this.width > 0 && this.height > 0) {
            try {
                const img = ctx.getImageData(0, 0, this.width, this.height);
                for (let i = 0; i < img.data.length; i += 4) {
                    img.data[i]     ^= (Math.random() * 2 | 0);
                    img.data[i + 1] ^= (Math.random() * 2 | 0);
                    img.data[i + 2] ^= (Math.random() * 2 | 0);
                }
                ctx.putImageData(img, 0, 0);
            } catch (_) {
                // Swallow cross-origin canvas security errors silently
            }
        }
        return _origToDataURL.apply(this, arguments);
    };

    // ── 9. Remove Playwright-specific internal window globals ─────────────────
    try { delete window.__playwright;     } catch (_) {}
    try { delete window.__pw_manual;      } catch (_) {}
    try { delete window._playwrightClock; } catch (_) {}

    // ── 10. Hide document-level automation visibility flags ──────────────────
    Object.defineProperty(document, 'hidden',          { get: () => false,     configurable: true });
    Object.defineProperty(document, 'visibilityState', { get: () => 'visible', configurable: true });

    // ── 11. Conceal navigator.connection details (used for fingerprinting) ────
    try {
        Object.defineProperty(navigator, 'connection', {
            get: () => ({ rtt: 50, downlink: 10, effectiveType: '4g', saveData: false }),
            configurable: true,
        });
    } catch (_) {}

})();
"""

async def apply_stealth_vitals(page: Page) -> None:
    """
    Injects the full stealth JS payload as a page init-script.
    The script fires inside every new document context before any page-level JS executes.
    """
    try:
        await page.add_init_script(script=_STEALTH_JS)
        logger.debug("Stealth vitals injected successfully.")
    except Exception as exc:
        logger.warning("Stealth injection non-fatal error: %s", exc)
