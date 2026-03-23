"""Headless Chromium browser tool powered by Playwright."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from mimick.config import settings
from mimick.logger import get_logger
from mimick.tools.base import Tool, ToolResult, registry

from playwright.async_api import async_playwright


class BrowserTool(Tool):
    """Render pages in headless Chromium and extract information."""

    name = "browser"
    description = (
        "Render a page in a headless Chromium browser (Playwright). "
        "Use this instead of curl when the page relies on JavaScript rendering "
        "(SPAs, AngularJS, React, Vue). Returns the fully rendered DOM, "
        "discovered JS libraries with versions, all page links, and console messages. "
        "Can also execute custom JavaScript in the page context."
    )
    binary = ""

    async def run(self, **kwargs: Any) -> ToolResult:
        """Navigate to a URL and perform the requested browser action.

        Args:
            **kwargs: Must include ``url``.  Optional keys: ``action``
                (``extract_info``, ``get_rendered_html``, ``execute_js``,
                ``screenshot``), ``js_code``, ``wait_for``, ``cookie``,
                ``timeout``.

        Returns:
            A ToolResult containing the action output or an error message.
        """
        log = get_logger(f"tool.{self.name}")

        url: str = kwargs["url"]
        action: str = kwargs.get("action", "extract_info")
        js_code: str | None = kwargs.get("js_code")
        wait_for: str | None = kwargs.get("wait_for")
        cookie_str: str | None = kwargs.get("cookie")
        timeout: int = kwargs.get("timeout", 15000)

        log.debug("Browser %s: %s", action, url)

        console_messages: list[str] = []

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage"],
                )
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                )

                if cookie_str:
                    cookies = self._parse_cookies(cookie_str, url)
                    if cookies:
                        await context.add_cookies(cookies)

                page = await context.new_page()

                page.on(
                    "console",
                    lambda msg: console_messages.append(f"[{msg.type}] {msg.text}"),
                )

                try:
                    await page.goto(url, timeout=timeout, wait_until="networkidle")
                except Exception:
                    try:
                        await page.goto(
                            url, timeout=timeout, wait_until="domcontentloaded"
                        )
                    except Exception as nav_err:
                        await browser.close()
                        return ToolResult(
                            tool_name=self.name,
                            command=f"browser {action} {url}",
                            stdout="",
                            stderr=f"Navigation failed: {nav_err}",
                            return_code=1,
                        )

                if wait_for:
                    try:
                        await page.wait_for_selector(wait_for, timeout=5000)
                    except Exception:
                        pass

                await page.wait_for_timeout(1000)

                if action == "get_rendered_html":
                    result = await self._get_rendered_html(page)
                elif action == "execute_js":
                    result = await self._execute_js(page, js_code)
                elif action == "screenshot":
                    result = await self._screenshot(page, url)
                else:
                    result = await self._extract_info(page, console_messages)

                await browser.close()

                return ToolResult(
                    tool_name=self.name,
                    command=f"browser {action} {url}",
                    stdout=result,
                    stderr="",
                    return_code=0,
                )

        except Exception as e:
            log.error("Browser error: %s", e)
            return ToolResult(
                tool_name=self.name,
                command=f"browser {action} {url}",
                stdout="",
                stderr=f"Browser error: {e}",
                return_code=1,
            )

    def _parse_cookies(self, cookie_str: str, url: str) -> list[dict]:
        """Parse a semicolon-delimited cookie string into Playwright dicts."""
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        cookies = []
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                name, value = part.split("=", 1)
                cookies.append(
                    {
                        "name": name.strip(),
                        "value": value.strip(),
                        "domain": domain,
                        "path": "/",
                    }
                )
        return cookies

    async def _get_rendered_html(self, page: Any) -> str:
        """Return the fully rendered DOM HTML, truncated if necessary."""
        html = await page.content()
        if len(html) > 50000:
            html = (
                html[:50000] + f"\n\n... (truncated, {len(html) - 50000} chars omitted)"
            )
        return html

    async def _execute_js(self, page: Any, js_code: str | None) -> str:
        """Evaluate custom JavaScript in the page context and return the result."""
        if not js_code:
            return "Error: js_code parameter is required for action='execute_js'"
        try:
            result = await page.evaluate(js_code)
            return json.dumps(result, indent=2, default=str)
        except Exception as e:
            return f"JavaScript execution error: {e}"

    async def _screenshot(self, page: Any, url: str) -> str:
        """Capture a full-page screenshot and save it to the output directory."""
        screenshots_dir = settings.output_dir / "screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        safe_name = urlparse(url).netloc.replace(":", "_") + ".png"
        path = screenshots_dir / safe_name

        await page.screenshot(path=str(path), full_page=True)
        return f"Screenshot saved to {path}"

    async def _extract_info(self, page: Any, console_messages: list[str]) -> str:
        """Extract links, forms, scripts, cookies, and JS libraries from the page."""
        info = await page.evaluate("""() => {
            const result = {};

            result.title = document.title;

            result.links = [...new Set(
                Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(h => h && !h.startsWith('javascript:'))
            )].slice(0, 100);

            result.forms = Array.from(document.querySelectorAll('form')).map(f => ({
                action: f.action,
                method: f.method,
                inputs: Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                    name: i.name || i.id,
                    type: i.type || i.tagName.toLowerCase(),
                })),
            }));

            result.scripts = Array.from(document.querySelectorAll('script[src]'))
                .map(s => s.src).slice(0, 50);

            const libs = [];

            if (window.angular) {
                libs.push({name: 'AngularJS', version: window.angular.version ? window.angular.version.full : 'unknown'});
            }
            const ngVersion = document.querySelector('[ng-version]');
            if (ngVersion) {
                libs.push({name: 'Angular', version: ngVersion.getAttribute('ng-version')});
            }
            if (window.jQuery) {
                libs.push({name: 'jQuery', version: window.jQuery.fn ? window.jQuery.fn.jquery : 'unknown'});
            }
            const reactRoot = document.querySelector('[data-reactroot]') || document.querySelector('#root');
            if (reactRoot && reactRoot._reactRootContainer) {
                libs.push({name: 'React', version: 'detected (version in React DevTools)'});
            }
            if (window.React) {
                libs.push({name: 'React', version: window.React.version || 'unknown'});
            }
            if (window.Vue) {
                libs.push({name: 'Vue.js', version: window.Vue.version || 'unknown'});
            }
            if (window.__VUE__) {
                libs.push({name: 'Vue.js', version: 'detected'});
            }
            if (window.DOMPurify) {
                libs.push({name: 'DOMPurify', version: window.DOMPurify.version || 'unknown'});
            }
            if (window._) {
                libs.push({name: 'Lodash/Underscore', version: window._.VERSION || 'unknown'});
            }
            if (window.bootstrap) {
                libs.push({name: 'Bootstrap', version: window.bootstrap.Alert ? window.bootstrap.Alert.VERSION || 'unknown' : 'unknown'});
            }

            const allScripts = Array.from(document.querySelectorAll('script'));
            const versionPatterns = [
                /angular[.\\/-]v?(\\d+\\.\\d+\\.\\d+)/i,
                /jquery[.\\/-]v?(\\d+\\.\\d+\\.\\d+)/i,
                /vue[.\\/-]v?(\\d+\\.\\d+\\.\\d+)/i,
                /react[.\\/-]v?(\\d+\\.\\d+\\.\\d+)/i,
                /bootstrap[.\\/-]v?(\\d+\\.\\d+\\.\\d+)/i,
                /dompurify[.\\/-]v?(\\d+\\.\\d+\\.\\d+)/i,
                /swagger-ui[.\\/-]v?(\\d+\\.\\d+\\.\\d+)/i,
                /moment[.\\/-]v?(\\d+\\.\\d+\\.\\d+)/i,
            ];
            const scriptSources = allScripts.map(s => s.src || '').join(' ') + ' ' +
                                  allScripts.map(s => (s.textContent || '').slice(0, 500)).join(' ');
            for (const pat of versionPatterns) {
                const m = scriptSources.match(pat);
                if (m) {
                    const libName = m[0].split(/[.\\/\\/-]/)[0];
                    const existing = libs.find(l => l.name.toLowerCase().includes(libName.toLowerCase()));
                    if (!existing) {
                        libs.push({name: libName, version: m[1]});
                    }
                }
            }

            result.libraries = libs;

            result.body_text = document.body ? document.body.innerText.slice(0, 10000) : '';

            result.meta = Array.from(document.querySelectorAll('meta')).map(m => ({
                name: m.name || m.getAttribute('property') || m.httpEquiv || '',
                content: m.content || '',
            })).filter(m => m.name);

            result.template_injection_markers = [];
            if (bodyHtml.includes('49') && bodyHtml.match(/\\b49\\b/)) {
                result.template_injection_markers.push('Possible CSTI: found "49" in rendered HTML (could be {{7*7}} evaluation)');
            }
            if (bodyHtml.match(/ng-app|ng-controller|ng-bind/)) {
                result.template_injection_markers.push('AngularJS directives found in DOM - CSTI likely possible');
            }

            return result;
        }""")

        cookies = await page.context.cookies()
        cookie_info = []
        for c in cookies:
            flags = []
            if c.get("httpOnly"):
                flags.append("HttpOnly")
            if c.get("secure"):
                flags.append("Secure")
            if c.get("sameSite") and c["sameSite"] != "None":
                flags.append(f"SameSite={c['sameSite']}")
            missing = []
            if not c.get("httpOnly"):
                missing.append("HttpOnly")
            if not c.get("secure"):
                missing.append("Secure")
            if not c.get("sameSite") or c["sameSite"] == "None":
                missing.append("SameSite")
            cookie_info.append(
                {
                    "name": c["name"],
                    "domain": c.get("domain", ""),
                    "flags_present": flags,
                    "flags_missing": missing,
                }
            )

        parts = []
        parts.append(f"=== Page Title: {info.get('title', 'N/A')} ===\n")

        if info.get("libraries"):
            parts.append("=== JS Libraries Detected ===")
            for lib in info["libraries"]:
                parts.append(f"  - {lib['name']}: {lib['version']}")
            parts.append("")

        if info.get("template_injection_markers"):
            parts.append("=== Template Injection Markers ===")
            for m in info["template_injection_markers"]:
                parts.append(f"  ⚠ {m}")
            parts.append("")

        if cookie_info:
            parts.append("=== Cookies ===")
            for c in cookie_info:
                parts.append(f"  - {c['name']} (domain: {c['domain']})")
                if c["flags_present"]:
                    parts.append(f"    Present: {', '.join(c['flags_present'])}")
                if c["flags_missing"]:
                    parts.append(f"    MISSING: {', '.join(c['flags_missing'])}")
            parts.append("")

        if info.get("links"):
            parts.append(f"=== Links ({len(info['links'])} found) ===")
            for link in info["links"][:50]:
                parts.append(f"  {link}")
            if len(info["links"]) > 50:
                parts.append(f"  ... and {len(info['links']) - 50} more")
            parts.append("")

        if info.get("forms"):
            parts.append("=== Forms ===")
            for i, form in enumerate(info["forms"]):
                parts.append(
                    f"  Form {i + 1}: {form['method'].upper()} {form['action']}"
                )
                for inp in form["inputs"]:
                    parts.append(f"    - {inp['name']} ({inp['type']})")
            parts.append("")

        if info.get("scripts"):
            parts.append("=== External Scripts ===")
            for s in info["scripts"][:20]:
                parts.append(f"  {s}")
            parts.append("")

        if console_messages:
            parts.append("=== Console Output ===")
            for msg in console_messages[:30]:
                parts.append(f"  {msg}")
            parts.append("")

        if info.get("body_text"):
            text = info["body_text"]
            parts.append("=== Rendered Text Content ===")
            parts.append(text[:5000])
            if len(text) > 5000:
                parts.append(f"\n... ({len(text) - 5000} chars truncated)")

        return "\n".join(parts)


registry.register(BrowserTool())
