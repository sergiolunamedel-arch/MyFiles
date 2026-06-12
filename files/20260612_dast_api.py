"""dast_api.py — DAST crawler + API security scanner engines.

Exposes:
    DastConfig, ApiConfig  (dataclasses)
    run_dast(cfg, out_dir, log, cancel) → (summary_dict, path)
    run_api(cfg, out_dir, log, cancel)  → (summary_dict, path)

Internal helpers (_make_opener, _fetch, _Throttle, …) are kept here and NOT
re-exported; only the two run_* functions and the config dataclasses are part
of the public API.
"""

from __future__ import annotations

import base64, json, re as _re, ssl, threading, time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import (urlparse, urljoin, urlencode,
                          parse_qsl, urlunparse)
from urllib.request import Request, build_opener, HTTPCookieProcessor
from urllib.error import URLError, HTTPError
from http.cookiejar import CookieJar


# ── Shared network constants ──────────────────────────────────────────────────
_DAST_UA  = "VulnScanner-DAST/1.0 (+local security testing)"
_DAST_SVR = {"critical": 4, "high": 3, "medium": 2, "low": 1}

_XSS_PROBE  = "xss<svg/onload=1>vsxx"
_SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "pg_query()", "psql:", "sqlite3.OperationalError",
    "ORA-00933", "SQLSTATE[", "Microsoft OLE DB Provider for SQL Server",
]

_DISC_PATHS = [
    ("/.env", ".env file exposed", "critical"),
    ("/.env.local", ".env.local file exposed", "critical"),
    ("/.env.production", ".env.production exposed", "critical"),
    ("/.git/HEAD", ".git repository exposed", "high"),
    ("/.git/config", ".git config exposed", "high"),
    ("/.svn/entries", ".svn metadata exposed", "high"),
    ("/.hg/requires", "Mercurial metadata exposed", "high"),
    ("/.DS_Store", ".DS_Store directory leak", "low"),
    ("/server-status", "Apache server-status exposed", "high"),
    ("/phpinfo.php", "phpinfo() page exposed", "high"),
    ("/info.php", "phpinfo() page exposed", "high"),
    ("/wp-config.php.bak", "WordPress config backup", "critical"),
    ("/.htpasswd", ".htpasswd exposed", "critical"),
    ("/.htaccess", ".htaccess exposed", "medium"),
    ("/web.config", "web.config exposed", "medium"),
    ("/.aws/credentials", "AWS credentials file exposed", "critical"),
    ("/.npmrc", ".npmrc (may leak tokens)", "high"),
    ("/.dockercfg", "Docker auth config exposed", "high"),
    ("/Dockerfile", "Dockerfile exposed", "low"),
    ("/docker-compose.yml", "docker-compose.yml exposed", "medium"),
    ("/.gitlab-ci.yml", "CI pipeline config exposed", "low"),
    ("/backup.zip", "backup.zip exposed", "high"),
    ("/backup.sql", "SQL dump exposed", "critical"),
    ("/db.sqlite", "SQLite database exposed", "critical"),
    ("/actuator/env", "Spring actuator /env exposed", "critical"),
    ("/actuator/health", "Spring actuator /health", "low"),
    ("/actuator/heapdump", "Spring actuator heapdump", "critical"),
    ("/api/docs", "Swagger/OpenAPI docs public", "low"),
    ("/swagger-ui.html", "Swagger UI public", "low"),
    ("/v2/api-docs", "Swagger v2 spec public", "low"),
    ("/openapi.json", "OpenAPI spec public", "low"),
    ("/.well-known/security.txt", "security.txt present (info)", "low"),
]

_SEC_HEADERS = [
    ("strict-transport-security", "Missing HSTS", "medium"),
    ("content-security-policy", "Missing Content-Security-Policy", "medium"),
    ("x-content-type-options", "Missing X-Content-Type-Options", "low"),
    ("x-frame-options", "Missing X-Frame-Options", "low"),
    ("referrer-policy", "Missing Referrer-Policy", "low"),
    ("permissions-policy", "Missing Permissions-Policy", "low"),
    ("cross-origin-opener-policy", "Missing Cross-Origin-Opener-Policy", "low"),
    ("cross-origin-resource-policy", "Missing Cross-Origin-Resource-Policy", "low"),
]

_DIRLIST_MARKERS = (
    "<title>index of /", "directory listing for",
    "<h1>index of /", "[to parent directory]")

_API_REDIRECT = ("next", "redirect", "url", "return",
                 "returnto", "dest", "callback")

# ── Selenium macro JS (injected into recorder browser) ────────────────────────
# Robust recorder. Key design points that fix the "captured 0 interactions" bug:
#   • Events are persisted to sessionStorage, NOT a bare window variable, so they
#     survive the navigation that login inevitably triggers (same-origin nav keeps
#     sessionStorage intact; the Python side ALSO drains it every poll so even a
#     cross-origin jump loses at most one polling window of events).
#   • We listen to `input` (fires on every keystroke → captures the final value
#     even if the field never blurs), `change`, `click`, AND — crucially — the
#     form `submit` event and an Enter `keydown`. A login submitted with the Enter
#     key fires `submit` but never a `click`; the old recorder missed it entirely.
#   • Selectors prefer #id, then data-testid, name, aria-label, then a short
#     structural path — industry-standard locator priority.
#   • Password VALUES are captured so the login can be replayed for the logout
#     recorder, but they stay in the running session only and are stripped from
#     every saved profile / condition file.
_MACRO_JS = r"""
(function(){
  if (window.__macro_installed) return;
  window.__macro_installed = true;
  var KEY = '__vulnscan_macro__';

  function load(){ try { return JSON.parse(sessionStorage.getItem(KEY) || '[]'); } catch(e){ return []; } }
  function save(a){ try { sessionStorage.setItem(KEY, JSON.stringify(a)); } catch(e){} }
  function push(entry){
    var a = load();
    entry.i   = (a.length ? a[a.length-1].i : 0) + 1;
    entry.url = location.href;
    a.push(entry); save(a);
  }

  function esc(s){
    return (window.CSS && CSS.escape) ? CSS.escape(s)
      : String(s).replace(/[^a-zA-Z0-9_-]/g, function(c){ return '\\' + c; });
  }
  function attr(el, name){ try { return el.getAttribute(name); } catch(e){ return null; } }
  function sel(el){
    if (!el || el.nodeType !== 1) return null;
    var tag = el.tagName.toLowerCase();
    if (el.id) return '#' + esc(el.id);
    var dt = attr(el,'data-testid') || attr(el,'data-test') || attr(el,'data-cy') || attr(el,'data-qa');
    if (dt) return tag + '[data-testid="' + String(dt).replace(/"/g,'\\"') + '"]';
    if (el.name) return tag + '[name="' + esc(el.name) + '"]';
    var al = attr(el,'aria-label');
    if (al) return tag + '[aria-label="' + String(al).replace(/"/g,'\\"').slice(0,60) + '"]';
    var parts = [], p = el, depth = 0;
    while (p && p.nodeType === 1 && depth < 5){
      if (p.id){ parts.unshift('#' + esc(p.id)); break; }
      var n = p.tagName.toLowerCase();
      if (p.classList && p.classList.length)
        n += '.' + Array.from(p.classList).slice(0,2).map(esc).join('.');
      var par = p.parentNode;
      if (par){
        var idx = Array.from(par.children).indexOf(p) + 1;
        if (idx) n += ':nth-child(' + idx + ')';
      }
      parts.unshift(n); p = p.parentElement; depth++;
    }
    return parts.join(' > ');
  }

  function role(el){
    var type = (el.type || '').toLowerCase();
    var ac   = (attr(el,'autocomplete') || '').toLowerCase();
    if (type === 'password' || ac === 'current-password' || ac === 'new-password') return 'password';
    if (ac === 'username' || ac === 'email' || type === 'email') return 'username';
    var hay = ((el.name||'')+' '+(el.id||'')+' '+(el.placeholder||'')+' '+(attr(el,'aria-label')||'')).toLowerCase();
    if (/(user|email|e-?mail|login|logon|correo|usuario|account|cuenta|phone|tel|m[oó]vil|dni|nif|rfc|curp)/.test(hay)) return 'username';
    return 'other';
  }

  function recordField(el){
    if (!el || !('value' in el) || el.type === 'hidden') return;
    var r = role(el);
    // Password values ARE captured so the login can be auto-replayed later, but
    // they live only in the running session — never written to any saved file.
    push({ kind:'field', selector: sel(el), value: el.value,
           ftype: (el.type || 'text').toLowerCase(), role: r });
  }

  document.addEventListener('input',  function(e){ recordField(e.target); }, true);
  document.addEventListener('change', function(e){ recordField(e.target); }, true);
  document.addEventListener('click',  function(e){
    if (!e.isTrusted) return;
    var t = e.target;
    var b = (t && t.closest) ? t.closest('button,a,input[type=submit],input[type=button],[role=button]') : null;
    var tgt = b || t;
    push({ kind:'click', selector: sel(tgt),
           text: ((tgt.innerText || tgt.value || '') + '').trim().slice(0,60) });
  }, true);
  document.addEventListener('submit', function(e){
    var f = e.target;
    var b = (f && f.querySelector)
      ? f.querySelector('button[type=submit],input[type=submit],button:not([type])') : null;
    push({ kind:'submit', form: sel(f), button: b ? sel(b) : null });
  }, true);
  document.addEventListener('keydown', function(e){
    if (!e.isTrusted || e.key !== 'Enter') return;
    var t = e.target;
    if (t && 'value' in t) recordField(t);          // flush the current value first
    var f = (t && t.form) ? t.form : (t && t.closest ? t.closest('form') : null);
    push({ kind:'enter', selector: sel(t), form: f ? sel(f) : null });
  }, true);
})();
"""

# Reads (and clears) the buffered events. Python calls this every poll so that
# events captured just before a navigation are pulled out before the page that
# holds them can be torn down.
_MACRO_DRAIN_JS = r"""
return (function(){
  try {
    var KEY = '__vulnscan_macro__';
    var raw = sessionStorage.getItem(KEY) || '[]';
    sessionStorage.setItem(KEY, '[]');
    return raw;
  } catch(e){ return '[]'; }
})();
"""

# NOTE: Selenium's execute_script only hands a value back to Python when the
# script *itself* runs a top-level `return`. A bare IIFE — `(function(){…})();`
# — evaluates but returns nothing, so the previous version always gave Python
# `None` and the capture popup came up blank. The leading `return` below is the
# fix; everything after it is wrapped in an IIFE purely for local scoping.
_LOGOUT_CAPTURE_JS = r"""
return (function(){
    var url   = window.location.href;
    var title = document.title || '';
    var hints = [];
    var seen  = {};
    // NOTE: no `form` or other big containers here — a form's innerText is the
    // whole multi-line form text, which used to flood the review popup with a
    // giant blob. Containers are summarised by the has_* flags below instead.
    var nodes = document.querySelectorAll(
        'h1,h2,input[type=email],input[type=text],input[type=password],' +
        'input[name*=user],input[name*=login],a[href*=login],a[href*=signin],' +
        'button,input[type=submit]');
    nodes.forEach(function(el){
        // Skip invisible elements — they aren't evidence of anything on screen.
        if (el.offsetParent === null && el.tagName !== 'INPUT') return;
        var t = (el.innerText||el.value||el.placeholder||'')+'';
        t = t.replace(/\s+/g,' ').trim().slice(0,80);   // collapse newlines/runs
        if(!t || seen[t.toLowerCase()]) return;
        seen[t.toLowerCase()] = 1;
        hints.push(t);
    });
    // Strong signals that this is a logged-OUT page: a password field and/or a
    // recognisable login form re-appeared. The GUI uses these to help the user
    // confirm they really reached the logout state.
    var hasPassword  = !!document.querySelector('input[type=password]');
    var hasLoginForm = !!document.querySelector(
        'form[action*=login],form[action*=signin],form[id*=login],' +
        'form[class*=login],form[id*=signin],form[class*=signin]');
    return JSON.stringify({
        url: url,
        title: title,
        hints: hints.slice(0, 12),
        has_password_field: hasPassword,
        has_login_form: hasLoginForm
    });
})();
"""


# ── Dataclasses ───────────────────────────────────────────────────────────────
@dataclass
class DastConfig:
    url: str = ""
    auth_type: str = "none"
    username: str = "";     password: str = ""
    token: str = "";        cookie: str = ""
    header_name: str = "";  header_value: str = ""
    login_url: str = "";    login_data: str = ""
    profile: str = "passive"; max_pages: int = 30
    timeout: int = 12;      verify_tls: bool = True
    include_subdomains: bool = False
    selenium_browser: str = "chrome"; selenium_binary: str = ""
    selenium_headless: bool = True
    selenium_wait_seconds: int = 15
    selenium_login_url: str = "";      selenium_user_selector: str = ""
    selenium_user_value: str = "";     selenium_pass_selector: str = ""
    selenium_pass_value: str = "";     selenium_submit_selector: str = ""
    selenium_extra_steps: str = ""
    selenium_macro: str = ""   # full ordered recording, replayed step-by-step
    login_success_selector: str = "";  login_success_text: str = ""
    logout_url_re: str = "";           auto_relogin: bool = True
    exclude_re: str = r"(?i)/(logout|signout|sign-out|log-out|api/logout)\b"
    rate_limit_rps: float = 8.0;       proxy: str = ""
    concurrency: int = 4


@dataclass
class ApiConfig:
    spec_source: str = "";  base_url: str = ""
    auth_type: str = "none"
    username: str = "";     password: str = ""
    token: str = "";        cookie: str = ""
    header_name: str = "";  header_value: str = ""
    profile: str = "passive"; max_endpoints: int = 80
    timeout: int = 12;      verify_tls: bool = True
    rate_limit_rps: float = 8.0; proxy: str = ""
    exclude_re: str = r"(?i)/(logout|signout|sign-out|log-out)\b"
    concurrency: int = 6
    url: str = ""   # duck-typing for _make_opener


# ── Network primitives ────────────────────────────────────────────────────────
class _Throttle:
    """Token-bucket-ish spacer. Thread-safe across a ThreadPoolExecutor."""
    def __init__(self, rps: float):
        self._min = (1.0 / rps) if rps and rps > 0 else 0.0
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self):
        if self._min <= 0: return
        with self._lock:
            now = time.monotonic()
            sleep_for = self._next - now
            self._next = max(now, self._next) + self._min
        if sleep_for > 0:
            time.sleep(sleep_for)


def _make_opener(cfg) -> tuple[Any, CookieJar, dict]:
    jar = CookieJar()
    ctx = ssl.create_default_context()
    if not cfg.verify_tls:
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    from urllib.request import HTTPSHandler, ProxyHandler
    handlers: list = [HTTPCookieProcessor(jar), HTTPSHandler(context=ctx)]
    if cfg.proxy:
        handlers.append(ProxyHandler({"http": cfg.proxy, "https": cfg.proxy}))
    opener = build_opener(*handlers)
    hdrs = {"User-Agent": _DAST_UA, "Accept": "*/*"}
    if   cfg.auth_type == "basic"  and cfg.username:
        tok = base64.b64encode(
            f"{cfg.username}:{cfg.password}".encode()).decode()
        hdrs["Authorization"] = f"Basic {tok}"
    elif cfg.auth_type == "bearer" and cfg.token:
        hdrs["Authorization"] = f"Bearer {cfg.token}"
    elif cfg.auth_type == "cookie" and cfg.cookie:
        hdrs["Cookie"] = cfg.cookie
    elif cfg.auth_type == "header" and cfg.header_name:
        hdrs[cfg.header_name] = cfg.header_value
    return opener, jar, hdrs


def _clone_opener(cfg, jar: CookieJar):
    """Build an independent opener carrying a snapshot of jar's cookies."""
    from urllib.request import HTTPSHandler, ProxyHandler
    ctx = ssl.create_default_context()
    if not getattr(cfg, "verify_tls", True):
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    new_jar = CookieJar()
    for c in jar:
        try: new_jar.set_cookie(c)
        except Exception: pass
    handlers: list = [HTTPCookieProcessor(new_jar), HTTPSHandler(context=ctx)]
    if getattr(cfg, "proxy", ""):
        handlers.append(
            ProxyHandler({"http": cfg.proxy, "https": cfg.proxy}))
    return build_opener(*handlers)


def _fetch(opener, hdrs, url, *, method="GET", data=None,
           timeout=12, extra=None) -> tuple[int, dict, bytes, str]:
    req = Request(url, data=data, method=method,
                  headers={**hdrs, **(extra or {})})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(1_500_000), r.geturl()
    except HTTPError as e:
        try: body = e.read(500_000)
        except Exception: body = b""
        return e.code, dict(e.headers or {}), body, url
    except (URLError, TimeoutError, ssl.SSLError, ConnectionError) as e:
        return 0, {}, b"", f"error: {e!r}"


def _inject_cookies(jar: CookieJar, cookies: list[dict]) -> None:
    from http.cookiejar import Cookie
    for c in cookies:
        domain = c.get("domain", "") or ""
        jar.set_cookie(Cookie(
            version=0, name=c["name"], value=c.get("value") or "",
            port=None, port_specified=False, domain=domain,
            domain_specified=bool(domain),
            domain_initial_dot=domain.startswith("."),
            path=c.get("path") or "/", path_specified=True,
            secure=bool(c.get("secure")),
            expires=c.get("expiry") or c.get("expires"),
            discard=False, comment=None, comment_url=None,
            rest={"HttpOnly": ""} if c.get("httpOnly") else {},
            rfc2109=False))


def _same_origin(base: str, candidate: str, subdomains: bool) -> bool:
    try:
        b, c = urlparse(base), urlparse(candidate)
        if c.scheme not in ("http", "https"): return False
        if subdomains:
            return bool(c.hostname) and (
                c.hostname == b.hostname
                or c.hostname.endswith("." + (b.hostname or "")))
        return c.hostname == b.hostname and (c.port or 0) == (b.port or 0)
    except Exception:
        return False


# ── HTML helpers ──────────────────────────────────────────────────────────────
class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._cur_form: Optional[dict] = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._cur_form = {"action": a.get("action") or "",
                              "method": (a.get("method") or "get").lower(),
                              "inputs": []}
        elif tag in ("input", "textarea", "select") and self._cur_form is not None:
            self._cur_form["inputs"].append(
                {"name": a.get("name") or "", "value": a.get("value") or "test"})

    def handle_endtag(self, tag):
        if tag == "form" and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None


# ── Passive header helpers (shared between DAST & API) ────────────────────────
def _passive_header_findings(lower: dict, fu: str, add) -> None:
    if "server" in lower:
        add("low", f"Server banner leak: {lower['server']}", fu,
            f"Server: {lower['server']}", "CWE-200", "headers")
    if "x-powered-by" in lower:
        add("low", f"X-Powered-By leak: {lower['x-powered-by']}", fu,
            f"X-Powered-By: {lower['x-powered-by']}", "CWE-200", "headers")
    acao  = lower.get("access-control-allow-origin")
    acred = (lower.get("access-control-allow-credentials") or "").lower() == "true"
    if acao == "*" and acred:
        add("high", "CORS: ACAO=* with credentials", fu,
            "ACAO=*  ACAC=true", "CWE-942", "cors")
    elif acao == "*":
        add("low", "CORS: Access-Control-Allow-Origin: *", fu,
            "ACAO=*", "CWE-942", "cors")


# ── Browser detection ─────────────────────────────────────────────────────────
# Maps each supported browser key to the WebDriver engine it needs.
#   chromium → ChromeDriver (Chrome/Brave/Opera/Opera GX/Vivaldi/Chromium)
#   edge     → EdgeDriver
#   firefox  → GeckoDriver
_BROWSER_ENGINE = {
    "chrome": "chromium", "chromium": "chromium", "brave": "chromium",
    "opera": "chromium", "opera_gx": "chromium", "vivaldi": "chromium",
    "edge": "edge", "firefox": "firefox",
}


def detect_browsers() -> "dict[str, dict]":
    """Probe the host for installed browsers.

    Returns an *ordered* dict ``{key: {"name","binary","engine"}}`` containing
    ONLY browsers that are actually installed, so the UI never offers something
    that can't launch.  Pure stdlib — safe to call before Selenium is imported.
    """
    import os, shutil, platform
    system = platform.system()

    def _first(paths):
        for p in paths:
            if not p:
                continue
            q = os.path.expandvars(os.path.expanduser(p))
            looks_like_path = (os.sep in q) or ("/" in q) or (":" in q[1:3])
            if looks_like_path:
                if os.path.exists(q):
                    return q
            else:
                w = shutil.which(q)
                if w:
                    return w
        return None

    if system == "Windows":
        catalog = [
            ("chrome", "Google Chrome", "chromium", [
                r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
                r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
                r"%LocalAppData%\Google\Chrome\Application\chrome.exe"]),
            ("edge", "Microsoft Edge", "edge", [
                r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
                r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"]),
            ("firefox", "Mozilla Firefox", "firefox", [
                r"%ProgramFiles%\Mozilla Firefox\firefox.exe",
                r"%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe"]),
            ("brave", "Brave", "chromium", [
                r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe",
                r"%ProgramFiles(x86)%\BraveSoftware\Brave-Browser\Application\brave.exe",
                r"%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe"]),
            ("opera", "Opera", "chromium", [
                r"%LocalAppData%\Programs\Opera\opera.exe",
                r"%ProgramFiles%\Opera\opera.exe",
                r"%ProgramFiles(x86)%\Opera\opera.exe"]),
            ("opera_gx", "Opera GX", "chromium", [
                r"%LocalAppData%\Programs\Opera GX\opera.exe",
                r"%ProgramFiles%\Opera GX\opera.exe"]),
            ("vivaldi", "Vivaldi", "chromium", [
                r"%LocalAppData%\Vivaldi\Application\vivaldi.exe",
                r"%ProgramFiles%\Vivaldi\Application\vivaldi.exe"]),
            ("chromium", "Chromium", "chromium", [
                r"%LocalAppData%\Chromium\Application\chrome.exe",
                r"%ProgramFiles%\Chromium\Application\chrome.exe"]),
        ]
    elif system == "Darwin":
        catalog = [
            ("chrome", "Google Chrome", "chromium",
             ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]),
            ("edge", "Microsoft Edge", "edge",
             ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"]),
            ("firefox", "Mozilla Firefox", "firefox",
             ["/Applications/Firefox.app/Contents/MacOS/firefox"]),
            ("brave", "Brave", "chromium",
             ["/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"]),
            ("opera", "Opera", "chromium",
             ["/Applications/Opera.app/Contents/MacOS/Opera"]),
            ("opera_gx", "Opera GX", "chromium",
             ["/Applications/Opera GX.app/Contents/MacOS/Opera"]),
            ("vivaldi", "Vivaldi", "chromium",
             ["/Applications/Vivaldi.app/Contents/MacOS/Vivaldi"]),
            ("chromium", "Chromium", "chromium",
             ["/Applications/Chromium.app/Contents/MacOS/Chromium"]),
        ]
    else:  # Linux / *BSD
        catalog = [
            ("chrome", "Google Chrome", "chromium",
             ["google-chrome", "google-chrome-stable",
              "/usr/bin/google-chrome", "/opt/google/chrome/chrome"]),
            ("edge", "Microsoft Edge", "edge",
             ["microsoft-edge", "microsoft-edge-stable", "/usr/bin/microsoft-edge"]),
            ("firefox", "Mozilla Firefox", "firefox",
             ["firefox", "firefox-esr", "/usr/bin/firefox", "/snap/bin/firefox"]),
            ("brave", "Brave", "chromium",
             ["brave-browser", "brave", "/usr/bin/brave-browser"]),
            ("opera", "Opera", "chromium", ["opera", "/usr/bin/opera"]),
            ("vivaldi", "Vivaldi", "chromium",
             ["vivaldi", "vivaldi-stable", "/usr/bin/vivaldi"]),
            ("chromium", "Chromium", "chromium",
             ["chromium", "chromium-browser", "/usr/bin/chromium", "/snap/bin/chromium"]),
        ]

    found: "dict[str, dict]" = {}
    for key, name, engine, paths in catalog:
        binp = _first(paths)
        if binp:
            found[key] = {"name": name, "binary": binp, "engine": engine}
    return found


# ── Selenium driver factory ───────────────────────────────────────────────────
def _make_driver(cfg: DastConfig, *, headless: bool,
                 log: Callable[[str], None] = lambda _: None):
    from selenium import webdriver

    browser = (cfg.selenium_browser or "chrome").lower()
    engine  = _BROWSER_ENGINE.get(browser, "chromium")
    binary  = (getattr(cfg, "selenium_binary", "") or "").strip()

    # Resolve the binary from on-disk detection when the GUI didn't pass one and
    # the browser isn't one that Selenium Manager finds on its own.
    if not binary and browser not in ("chrome", "edge", "firefox"):
        try:
            d = detect_browsers().get(browser)
            if d:
                binary = d["binary"]
        except Exception:
            pass

    log(f"[dast] launching {browser} (engine={engine}, headless={headless}, "
        f"binary={binary or 'auto'})")

    # ── Firefox ──────────────────────────────────────────────────────────────
    if engine == "firefox":
        opts = webdriver.FirefoxOptions()
        if headless: opts.add_argument("-headless")
        if binary:   opts.binary_location = binary
        try: opts.page_load_strategy = "eager"
        except Exception: pass
        if not cfg.verify_tls: opts.accept_insecure_certs = True
        if cfg.proxy:
            host, _, port = cfg.proxy.replace("http://", "").replace("https://", "").partition(":")
            opts.set_preference("network.proxy.type", 1)
            for scheme in ("http", "ssl"):
                opts.set_preference(f"network.proxy.{scheme}", host)
                opts.set_preference(f"network.proxy.{scheme}_port", int(port or 8080))
        try:
            return webdriver.Firefox(options=opts)               # Selenium Manager
        except Exception as e:
            log(f"[dast] Selenium Manager (firefox) failed ({e!r}); webdriver-manager")
            from webdriver_manager.firefox import GeckoDriverManager
            from selenium.webdriver.firefox.service import Service
            return webdriver.Firefox(
                service=Service(GeckoDriverManager().install()), options=opts)

    # Chromium/Edge startup is often dominated by first-run checks, component
    # updates, background networking and — the big one on Linux/macOS — the OS
    # keyring handshake, which can block for several seconds. These flags skip
    # all of that so the window opens promptly.
    def _chromium_speed(opts):
        for a in (
            "--no-first-run", "--no-default-browser-check", "--no-service-autorun",
            "--disable-extensions", "--disable-background-networking",
            "--disable-component-update", "--disable-default-apps",
            "--disable-sync", "--disable-translate",
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-renderer-backgrounding", "--metrics-recording-only",
            "--mute-audio", "--password-store=basic", "--use-mock-keychain",
            "--disable-features=Translate,OptimizationHints,MediaRouter,"
            "CalculateNativeWinOcclusion",
        ):
            opts.add_argument(a)
        try: opts.page_load_strategy = "eager"   # return on DOMContentLoaded
        except Exception: pass
        return opts

    # ── Edge ─────────────────────────────────────────────────────────────────
    if engine == "edge":
        from selenium.webdriver.edge.options import Options as EdgeOptions
        opts = EdgeOptions()
        if headless: opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox"); opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-gpu")
        _chromium_speed(opts)
        if binary: opts.binary_location = binary
        if not cfg.verify_tls:
            opts.add_argument("--ignore-certificate-errors")
            opts.set_capability("acceptInsecureCerts", True)
        if cfg.proxy: opts.add_argument(f"--proxy-server={cfg.proxy}")
        try:
            return webdriver.Edge(options=opts)                  # Selenium Manager
        except Exception as e:
            log(f"[dast] Selenium Manager (edge) failed ({e!r}); webdriver-manager")
            from webdriver_manager.microsoft import EdgeChromiumDriverManager
            from selenium.webdriver.edge.service import Service
            return webdriver.Edge(
                service=Service(EdgeChromiumDriverManager().install()), options=opts)

    # ── Chromium family (chrome, brave, opera, opera_gx, vivaldi, chromium) ──
    opts = webdriver.ChromeOptions()
    if headless: opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    _chromium_speed(opts)
    if binary: opts.binary_location = binary
    if not cfg.verify_tls:
        opts.add_argument("--ignore-certificate-errors")
        opts.set_capability("acceptInsecureCerts", True)
    if cfg.proxy: opts.add_argument(f"--proxy-server={cfg.proxy}")

    try:
        return webdriver.Chrome(options=opts)                    # Selenium Manager
    except Exception as e:
        log(f"[dast] Selenium Manager (chromium) failed ({e!r}); webdriver-manager")
        from webdriver_manager.chrome import ChromeDriverManager
        from selenium.webdriver.chrome.service import Service
        try:
            from webdriver_manager.core.os_manager import ChromeType
            ctype = (ChromeType.BRAVE if browser == "brave"
                     else ChromeType.CHROMIUM if browser == "chromium"
                     else ChromeType.GOOGLE)
            svc = Service(ChromeDriverManager(chrome_type=ctype).install())
        except Exception:
            svc = Service(ChromeDriverManager().install())
        return webdriver.Chrome(service=svc, options=opts)


def _replay_login_macro(driver, macro, *, pass_value=None, wait_seconds=15,
                        log=lambda *_: None) -> bool:
    """Replay a recorded login the way ZAP/Burp do: execute EVERY recorded
    interaction in the EXACT order it happened — click that opens the overlay,
    then username, then password, then submit. No reordering, no guessing, no
    re-clicking the trigger (which on toggle overlays just closes them again).

    `macro` is the list of events captured by _MACRO_JS (kinds: field, click,
    submit, enter). `pass_value` is injected at runtime for any recorded
    password field whose value wasn't saved (passwords are never written to
    disk). Returns True if a password value was actually typed into a VISIBLE
    field (our proxy for "the form was really driven")."""
    import time as _t
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys

    if not isinstance(macro, list) or not macro:
        return False

    def _visible(css, timeout):
        """First VISIBLE element matching css; searches main doc then iframes.
        Leaves the driver switched into the iframe on an iframe hit."""
        deadline = _t.time() + max(timeout, 0.3)
        while _t.time() < deadline:
            try:
                driver.switch_to.default_content()
                for el in driver.find_elements(By.CSS_SELECTOR, css):
                    try:
                        if el.is_displayed():
                            return el
                    except Exception:
                        continue
                for fr in driver.find_elements(By.TAG_NAME, "iframe"):
                    try:
                        driver.switch_to.default_content()
                        driver.switch_to.frame(fr)
                        for el in driver.find_elements(By.CSS_SELECTOR, css):
                            if el.is_displayed():
                                return el
                    except Exception:
                        continue
                driver.switch_to.default_content()
            except Exception:
                pass
            _t.sleep(0.2)
        try: driver.switch_to.default_content()
        except Exception: pass
        return None

    def _type(el, val):
        try: el.click()
        except Exception: pass
        try: el.clear()
        except Exception: pass
        try: el.send_keys(val)
        except Exception as e:
            log(f"[replay] send_keys failed: {e!r}")
        try:
            if (el.get_attribute("value") or "") == str(val):
                return True
            driver.execute_script(
                "arguments[0].value=arguments[1];"
                "arguments[0].dispatchEvent(new Event('input',{bubbles:true}));"
                "arguments[0].dispatchEvent(new Event('change',{bubbles:true}));",
                el, str(val))
            return (el.get_attribute("value") or "") != ""
        except Exception:
            return False

    typed_password = False
    per_wait = max(2, min(int(wait_seconds or 15), 12))

    for step in macro:
        if not isinstance(step, dict):
            continue
        kind = step.get("kind")
        sel  = step.get("selector")
        try:
            if kind == "field":
                if not sel:
                    continue
                is_pass = (step.get("role") == "password"
                           or step.get("ftype") == "password")
                val = step.get("value")
                if is_pass and (val in (None, "")) and pass_value:
                    val = pass_value          # inject runtime password
                if val in (None, ""):
                    continue
                el = _visible(sel, per_wait)
                if not el:
                    log(f"[replay] field not visible: {sel}")
                    continue
                if _type(el, val):
                    if is_pass:
                        typed_password = True
                        log("[replay] typed password")
                    else:
                        log(f"[replay] typed into {sel}")

            elif kind == "click":
                if not sel:
                    continue
                el = _visible(sel, per_wait)
                if el:
                    el.click()
                    log(f"[replay] clicked {sel}")
                    _t.sleep(0.6)            # let overlays/navigation settle
                else:
                    log(f"[replay] click target not visible: {sel}")

            elif kind == "enter":
                tgt = sel
                el = _visible(tgt, 2) if tgt else None
                if el:
                    el.send_keys(Keys.ENTER)
                    log("[replay] pressed Enter")
                    _t.sleep(0.6)
                elif step.get("form"):
                    driver.switch_to.default_content()
                    driver.execute_script(
                        "var f=document.querySelector(arguments[0]);"
                        "if(f){if(f.requestSubmit)f.requestSubmit();else f.submit();}",
                        step["form"])
                    log("[replay] submitted form (enter→form)")
                    _t.sleep(0.6)

            elif kind == "submit":
                # Prefer clicking the recorded submit button (keeps SPA handlers
                # intact); fall back to requestSubmit on the form.
                btn = step.get("button")
                frm = step.get("form")
                done = False
                if btn:
                    el = _visible(btn, 2)
                    if el:
                        el.click(); done = True
                        log("[replay] clicked submit button")
                        _t.sleep(0.6)
                if not done and frm:
                    driver.switch_to.default_content()
                    driver.execute_script(
                        "var fs=document.querySelectorAll(arguments[0]);"
                        "for(var i=0;i<fs.length;i++){if(fs[i].offsetParent!==null){"
                        "if(fs[i].requestSubmit)fs[i].requestSubmit();"
                        "else fs[i].submit();return;}}",
                        frm)
                    log("[replay] submitted form")
                    _t.sleep(0.6)
        except Exception as e:
            log(f"[replay] step {step!r} failed: {e!r}")

    try: driver.switch_to.default_content()
    except Exception: pass
    return typed_password


def _selenium_login(cfg: DastConfig,
                    log: Callable[[str], None]) -> list[dict]:
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    driver = _make_driver(cfg, headless=cfg.selenium_headless, log=log)
    try:
        wait      = WebDriverWait(driver, cfg.selenium_wait_seconds)
        login_url = cfg.selenium_login_url or cfg.login_url or cfg.url
        log(f"[dast] selenium: GET {login_url}")
        driver.get(login_url)

        # Preferred path: replay the full recording literally, in order. This is
        # how it survives overlay/iframe logins (XenForo etc.) — the recorded
        # "open login" click runs first, exactly as the user did it.
        used_macro = False
        if (cfg.selenium_macro or "").strip():
            try:
                macro = json.loads(cfg.selenium_macro)
            except Exception as e:
                log(f"[dast] selenium_macro JSON invalid: {e!r}"); macro = None
            if macro:
                _replay_login_macro(
                    driver, macro,
                    pass_value=(cfg.selenium_pass_value or cfg.password),
                    wait_seconds=cfg.selenium_wait_seconds, log=log)
                used_macro = True

        if not used_macro:
            # Legacy field-based path (older saved conditions without a macro).
            if cfg.selenium_user_selector:
                el = wait.until(EC.presence_of_element_located(
                    (By.CSS_SELECTOR, cfg.selenium_user_selector)))
                el.clear(); el.send_keys(cfg.selenium_user_value or cfg.username)
            if cfg.selenium_pass_selector:
                el = driver.find_element(By.CSS_SELECTOR, cfg.selenium_pass_selector)
                el.clear()
                el.send_keys(cfg.selenium_pass_value or cfg.password)
            if cfg.selenium_extra_steps.strip():
                try: steps = json.loads(cfg.selenium_extra_steps)
                except Exception as e:
                    log(f"[dast] extra_steps JSON invalid: {e!r}"); steps = []
                for s in steps or []:
                    try:
                        if "selector" in s and "value" in s:
                            el = driver.find_element(By.CSS_SELECTOR, s["selector"])
                            el.clear(); el.send_keys(str(s["value"]))
                        elif "click" in s:
                            driver.find_element(By.CSS_SELECTOR, s["click"]).click()
                        elif "key" in s and str(s["key"]).lower() == "enter":
                            from selenium.webdriver.common.keys import Keys
                            tgt = (s.get("selector") or cfg.selenium_pass_selector
                                   or cfg.selenium_user_selector)
                            if tgt:
                                driver.find_element(By.CSS_SELECTOR, tgt).send_keys(Keys.ENTER)
                        elif "submit" in s:
                            driver.execute_script(
                                "var f=document.querySelector(arguments[0]);"
                                "if(f){if(f.requestSubmit)f.requestSubmit();else f.submit();}",
                                s["submit"])
                        elif "wait"  in s: time.sleep(float(s["wait"]))
                        elif "js"    in s: driver.execute_script(s["js"])
                    except Exception as e:
                        log(f"[dast] step {s!r} failed: {e!r}")
            if cfg.selenium_submit_selector:
                driver.find_element(
                    By.CSS_SELECTOR, cfg.selenium_submit_selector).click()
        if cfg.login_success_selector:
            wait.until(EC.presence_of_element_located(
                (By.CSS_SELECTOR, cfg.login_success_selector)))
            log("[dast] selenium login OK (selector present)")
        elif cfg.login_success_text:
            wait.until(lambda d: cfg.login_success_text in d.page_source)
            log("[dast] selenium login OK (success text detected)")
        else:
            time.sleep(2); log("[dast] selenium login completed")
        cookies = driver.get_cookies() or []
        log(f"[dast] selenium captured {len(cookies)} cookie(s)")
        return cookies
    finally:
        try: driver.quit()
        except Exception: pass


# ── DAST engine ───────────────────────────────────────────────────────────────
def run_dast(cfg: DastConfig, out_dir: Path,
             log: Callable[[str], None],
             cancel: Optional[threading.Event] = None) -> tuple[dict, Path]:
    findings: list[dict] = []
    visited:  set[str]   = set()
    queued:   list[str]  = []
    forms:    list[tuple[str, dict]] = []
    cancel   = cancel or threading.Event()
    throttle = _Throttle(cfg.rate_limit_rps)
    stopped  = cancel.is_set
    _flock   = threading.Lock()

    def write_out(summary: dict) -> Path:
        out = out_dir / "dast.json"
        out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return out

    if not cfg.url:
        s = {"findings": [], "target": "", "profile": cfg.profile}
        return s, write_out({"findings": []})

    base = cfg.url.strip()
    if not base.startswith(("http://", "https://")): base = "http://" + base
    workers = max(1, min(int(getattr(cfg, "concurrency", 4) or 1), 16))
    log(f"[dast] target={base}  profile={cfg.profile}  max_pages={cfg.max_pages}  "
        f"rps={cfg.rate_limit_rps}  workers={workers}  proxy={cfg.proxy or 'none'}")

    exclude_re = None
    if cfg.exclude_re:
        try: exclude_re = _re.compile(cfg.exclude_re)
        except _re.error as e: log(f"[dast] invalid exclude_re: {e}")

    def is_excluded(u: str) -> bool:
        if exclude_re and exclude_re.search(u): return True
        if cfg.logout_url_re:
            try:
                if _re.search(cfg.logout_url_re, u): return True
            except _re.error: pass
        return False

    opener, jar, hdrs = _make_opener(cfg)

    def form_login():
        if not cfg.login_url or not cfg.login_data: return
        log(f"[dast] form login → {cfg.login_url}")
        _fetch(opener, hdrs, cfg.login_url, method="POST",
               data=cfg.login_data.encode(), timeout=cfg.timeout,
               extra={"Content-Type": "application/x-www-form-urlencoded"})

    if   cfg.auth_type == "form":     form_login()
    elif cfg.auth_type == "selenium":
        try: _inject_cookies(jar, _selenium_login(cfg, log))
        except Exception as e:
            log(f"[dast] selenium login FAILED: {e!r}")
            findings.append({"severity": "high", "title": "Selenium login failed",
                             "url": cfg.selenium_login_url or cfg.url,
                             "evidence": repr(e), "cwe": "CWE-287",
                             "category": "auth"})

    relogins = {"count": 0}; MAX_RELOGINS = 2

    def looks_logged_out(body: bytes, fu: str) -> bool:
        if cfg.logout_url_re:
            try:
                if _re.search(cfg.logout_url_re, fu): return True
            except _re.error: pass
        if cfg.login_success_text and body:
            try: return cfg.login_success_text not in body.decode("utf-8", errors="replace")
            except Exception: return False
        return False

    def fetch(url, *, method="GET", data=None, extra=None):
        throttle.wait()
        st, hh, bb, fu = _fetch(opener, hdrs, url, method=method, data=data,
                                 timeout=cfg.timeout, extra=extra)
        if cfg.auto_relogin and cfg.auth_type in ("form", "selenium") and \
                relogins["count"] < MAX_RELOGINS and looks_logged_out(bb, fu):
            log(f"[dast] session lost — re-authenticating ({cfg.auth_type})")
            relogins["count"] += 1
            try:
                if cfg.auth_type == "selenium":
                    cookies = _selenium_login(cfg, log)
                    jar.clear(); _inject_cookies(jar, cookies)
                else:
                    jar.clear(); form_login()
            except Exception as e:
                log(f"[dast] re-login failed: {e!r}")
                with _flock:
                    findings.append({"severity": "high",
                                     "title": "Re-authentication failed",
                                     "url": fu, "evidence": repr(e),
                                     "cwe": "CWE-287", "category": "auth"})
                return st, hh, bb, fu
            throttle.wait()
            st, hh, bb, fu = _fetch(opener, hdrs, url, method=method,
                                     data=data, timeout=cfg.timeout,
                                     extra=extra)
        return st, hh, bb, fu

    _tl = threading.local()

    def probe(url, *, method="GET", data=None, extra=None):
        o = getattr(_tl, "opener", None)
        if o is None:
            o = _clone_opener(cfg, jar); _tl.opener = o
        throttle.wait()
        return _fetch(o, hdrs, url, method=method, data=data,
                      timeout=cfg.timeout, extra=extra)

    keep_seq   = cfg.auto_relogin and cfg.auth_type in ("form", "selenium")
    parallel   = workers > 1 and not keep_seq
    scan_fetch = fetch if keep_seq else probe

    def _pool_map(fn, items):
        items = list(items)
        if parallel and len(items) > 1:
            with ThreadPoolExecutor(max_workers=workers) as ex_:
                for _ in ex_.map(fn, items): pass
        else:
            for it in items:
                if stopped(): break
                fn(it)

    def add(sev, title, url, evidence="", cwe="", category="general"):
        with _flock:
            findings.append({"severity": sev, "title": title, "url": url,
                             "evidence": (evidence or "")[:600],
                             "cwe": cwe, "category": category})

    parsed = urlparse(base)
    if parsed.scheme == "http":
        add("medium", "Application served over plain HTTP", base,
            "Traffic is unencrypted.", "CWE-319", "transport")

    status, hdrs_r, body, final_url = fetch(base)
    log(f"[dast] {status} GET {base} ({len(body)} bytes)")
    if status == 0:
        add("high", "Target unreachable or TLS handshake failed", base,
            final_url, "", "transport")
        s = {"target": base, "final_url": final_url, "profile": cfg.profile,
             "auth_type": cfg.auth_type, "pages_visited": 0,
             "forms_discovered": 0, "relogins": 0,
             "cancelled": stopped(), "findings": findings}
        return s, write_out(s)

    lower_hdrs = {k.lower(): v for k, v in hdrs_r.items()}
    if parsed.scheme == "https":
        for hname, title, sev in _SEC_HEADERS:
            if hname not in lower_hdrs:
                add(sev, title, final_url,
                    f"Response headers: {sorted(lower_hdrs.keys())}",
                    "CWE-693", "headers")
    _passive_header_findings(lower_hdrs, final_url, add)

    for c in jar:
        flags = []
        if not c.secure: flags.append("missing Secure")
        if not getattr(c, "_rest", {}).get("HttpOnly") and \
                "httponly" not in [k.lower() for k in (c._rest or {}).keys()]:
            flags.append("missing HttpOnly")
        if not next((v for k, v in (c._rest or {}).items()
                     if k.lower() == "samesite"), None):
            flags.append("missing SameSite")
        if flags:
            add("medium" if "Secure" in " ".join(flags) else "low",
                f"Cookie '{c.name}' has weak flags: {', '.join(flags)}",
                final_url, f"{c.name}={c.value[:30]}…",
                "CWE-614", "cookies")

    # ── Sensitive-path disclosure ─────────────────────────────────────────────
    def _disc(item):
        p, title, sev = item
        if stopped(): return
        u = urljoin(base, p)
        if is_excluded(u): return
        st, _, bb, _ = probe(u)
        if st and 200 <= st < 300 and len(bb) > 0:
            add(sev, title, u, f"HTTP {st}, {len(bb)} bytes",
                "CWE-538", "disclosure")

    if workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as ex_:
            list(ex_.map(_disc, _DISC_PATHS))
    else:
        for it in _DISC_PATHS:
            if stopped(): break
            _disc(it)

    # ── Crawl ─────────────────────────────────────────────────────────────────
    def _looks_like_dirlist(low_text: str) -> bool:
        head = low_text[:600]
        return any(m in head for m in _DIRLIST_MARKERS)

    def _ingest(u, st, hh2, bb2, fu2):
        if st == 0 or not bb2: return
        ctype = (hh2.get("Content-Type") or
                 hh2.get("content-type") or "").lower()
        if "html" not in ctype: return
        try: text = bb2.decode("utf-8", errors="replace")
        except Exception: return
        if _looks_like_dirlist(text.lower()):
            add("low", "Directory listing enabled", fu2,
                "Auto-generated index page returned.", "CWE-548", "disclosure")
        ex = _LinkExtractor()
        try: ex.feed(text)
        except Exception: pass
        for href in ex.links:
            nxt = urljoin(fu2, href).split("#", 1)[0]
            if (nxt in visited
                    or not _same_origin(base, nxt, cfg.include_subdomains)
                    or is_excluded(nxt)):
                continue
            visited.add(nxt); queued.append(nxt)
        for fm in ex.forms:
            forms.append((fu2, fm))

    queued.append(final_url); visited.add(final_url)
    pages = 0
    while queued and pages < cfg.max_pages and not stopped():
        remaining = cfg.max_pages - pages
        batch = []
        while (queued and len(batch) < (workers if parallel else 1)
               and len(batch) < remaining):
            cu = queued.pop(0)
            if is_excluded(cu): continue
            batch.append(cu)
        if not batch: break

        def _grab(u):
            if u == final_url:
                return (u, status, hdrs_r, body, final_url)
            st2, hh2, bb2, fu2 = scan_fetch(u)
            return (u, st2, hh2, bb2, fu2)

        if parallel and len(batch) > 1:
            with ThreadPoolExecutor(max_workers=workers) as ex_:
                results = list(ex_.map(_grab, batch))
        else:
            results = [_grab(u) for u in batch]

        for (_u, st2, hh2, bb2, fu2) in results:
            if stopped(): break
            pages += 1
            _ingest(_u, st2, hh2, bb2, fu2)

    log(f"[dast] crawl: {pages} pages, {len(forms)} forms")

    # ── Active probes ─────────────────────────────────────────────────────────
    if cfg.profile == "active":
        log(f"[dast] active probes: XSS / SQLi / open-redirect "
            f"({'concurrent' if parallel else 'sequential'})")

        def _probe_url(u):
            if stopped() or is_excluded(u): return
            p2 = urlparse(u); qs = parse_qsl(p2.query, keep_blank_values=True)
            if not qs: return
            for idx, (qk, _qv) in enumerate(qs):
                if stopped(): break
                base_qs = list(qs)
                # XSS
                xss = base_qs[:]; xss[idx] = (qk, _XSS_PROBE)
                xurl = urlunparse(p2._replace(query=urlencode(xss)))
                st3, _, bb3, _ = probe(xurl)
                if st3 and bb3 and _XSS_PROBE in bb3.decode("utf-8", errors="replace"):
                    add("high", f"Reflected XSS in param '{qk}'", xurl,
                        "Payload reflected.", "CWE-79", "xss")
                # SQLi
                sqli = base_qs[:]; sqli[idx] = (qk, str(_qv) + "'\"")
                surl = urlunparse(p2._replace(query=urlencode(sqli)))
                sts, _, bbs, _ = probe(surl)
                if sts and bbs:
                    low_s = bbs.decode("utf-8", errors="replace").lower()
                    hit = next((e for e in _SQL_ERRORS if e in low_s), None)
                    if hit:
                        add("critical", f"SQLi in param '{qk}'", surl,
                            f"DB error: {hit!r}", "CWE-89", "sqli")
                # Open redirect
                if qk.lower() in _API_REDIRECT:
                    rq = base_qs[:]; rq[idx] = (qk, "https://example.com/")
                    rurl = urlunparse(p2._replace(query=urlencode(rq)))
                    str_, rh, _, _ = probe(rurl)
                    loc = rh.get("Location") or rh.get("location") or ""
                    if (str_ in (301, 302, 303, 307, 308)
                            and loc.startswith("https://example.com")):
                        add("high", f"Open redirect via '{qk}'", rurl,
                            f"Location: {loc}", "CWE-601", "redirect")

        _pool_map(_probe_url, list(visited))

        def _probe_form(item):
            fu2, fm = item
            if stopped() or is_excluded(fu2): return
            action = urljoin(fu2, fm["action"]) if fm["action"] else fu2
            if is_excluded(action): return
            for inp in fm["inputs"]:
                if stopped(): break
                orig  = {i["name"]: i.get("value", "test")
                         for i in fm["inputs"] if i["name"]}
                probe_d = dict(orig)
                probe_d[inp["name"]] = _XSS_PROBE
                data = urlencode(probe_d).encode()
                st4, _, bb4, _ = probe(action, method=fm["method"].upper(),
                                       data=data,
                                       extra={"Content-Type":
                                              "application/x-www-form-urlencoded"})
                if st4 and bb4 and _XSS_PROBE in bb4.decode("utf-8", errors="replace"):
                    add("high", f"Form XSS in field '{inp['name']}'", action,
                        "Payload reflected.", "CWE-79", "xss")

        _pool_map(_probe_form, forms)

    findings.sort(key=lambda x: -_DAST_SVR.get(x["severity"], 0))
    summary = {
        "target": base, "final_url": final_url,
        "profile": cfg.profile, "auth_type": cfg.auth_type,
        "pages_visited": pages, "forms_discovered": len(forms),
        "relogins": relogins["count"],
        "cancelled": stopped(), "findings": findings,
    }
    if stopped(): log("[dast] scan cancelled by user")
    out_p = write_out(summary)
    log(f"[dast] complete: {len(findings)} findings → {out_p}")
    return summary, out_p


# ── API scanner helpers ───────────────────────────────────────────────────────
def _api_load_spec(opener, hdrs, cfg: ApiConfig,
                   log) -> Optional[dict]:
    src = (cfg.spec_source or "").strip()
    if not src: return None
    raw: Optional[str] = None
    if src.startswith(("http://", "https://")):
        log(f"[api] fetching spec: {src}")
        st, _, bb, _ = _fetch(opener, hdrs, src, timeout=cfg.timeout)
        if st and bb: raw = bb.decode("utf-8", errors="replace")
        else: log(f"[api] could not fetch spec (HTTP {st})"); return None
    else:
        p = Path(src)
        if not p.exists():
            log(f"[api] spec not found: {src}"); return None
        raw = p.read_text(encoding="utf-8", errors="replace")
    try: return json.loads(raw)
    except json.JSONDecodeError: pass
    try:
        import importlib
        yaml = importlib.import_module("yaml")
        return yaml.safe_load(raw)
    except Exception as e:
        log(f"[api] spec is neither JSON nor YAML: {e!r}"); return None


def _api_deref(spec: dict, node: Any, _seen=None) -> Any:
    seen = _seen or set()
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
            return node
        seen.add(ref); cur: Any = spec
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(cur, dict) and part in cur: cur = cur[part]
            else: return node
        node = cur
    return node


def _api_sample(spec: dict, schema: Any, depth: int = 0) -> Any:
    schema = _api_deref(spec, schema) or {}
    if not isinstance(schema, dict) or depth > 4: return "test"
    for k in ("example", "default"):
        if k in schema: return schema[k]
    if schema.get("enum"): return schema["enum"][0]
    t = schema.get("type")
    if t == "object" or "properties" in schema:
        props = schema.get("properties") or {}
        req = set(schema.get("required") or [])
        keys = [k for k in props if not req or k in req] or list(props)[:3]
        return {k: _api_sample(spec, props[k], depth + 1) for k in keys}
    if t == "array":   return [_api_sample(spec, schema.get("items") or {}, depth + 1)]
    if t in ("integer", "number"): return 1
    if t == "boolean": return True
    return {"date-time": "2020-01-01T00:00:00Z", "date": "2020-01-01",
            "email": "test@example.com",
            "uuid": "00000000-0000-0000-0000-000000000000"}.get(
                schema.get("format"), "test")


def _api_base_url(spec: dict, cfg: ApiConfig, spec_src: str) -> str:
    if cfg.base_url.strip(): base = cfg.base_url.strip()
    elif isinstance(spec.get("servers"), list) and spec["servers"]:
        base = (spec["servers"][0] or {}).get("url", "") or ""
    elif spec.get("host"):
        scheme = (spec.get("schemes") or ["https"])[0]
        base = f"{scheme}://{spec['host']}{spec.get('basePath', '')}"
    else: base = ""
    if base.startswith("/") or not base:
        if spec_src.startswith(("http://", "https://")):
            base = urljoin(spec_src, base or "/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base
    return base.rstrip("/")


def _api_ops_postman(coll: dict, base: str) -> list[dict]:
    ops: list[dict] = []

    def walk(items):
        for it in items or []:
            if "item" in it: walk(it["item"]); continue
            req = it.get("request")
            if not isinstance(req, dict): continue
            method = (req.get("method") or "GET").upper()
            u = req.get("url")
            if isinstance(u, dict):
                url   = u.get("raw") or ""
                query = [(q.get("key"), q.get("value") or "test")
                         for q in (u.get("query") or []) if q.get("key")]
            else: url = u or ""; query = []
            url = url.split("#", 1)[0]
            for var in _re.findall(r"\{\{(\w+)\}\}", url):
                url = url.replace("{{" + var + "}}", "test")
            url = _re.sub(r"/:(\w+)", "/test", url)
            if url and not url.startswith(("http://", "https://")) and base:
                url = base + ("/" + url.lstrip("/"))
            secured = bool(req.get("auth")) or any(
                (h.get("key") or "").lower() == "authorization"
                for h in (req.get("header") or []))
            body = ctype = json_body = None
            b = req.get("body") or {}
            if b.get("mode") == "raw" and b.get("raw"):
                try:
                    json_body = json.loads(b["raw"])
                    body = b["raw"].encode(); ctype = "application/json"
                except Exception: pass
            ops.append({"method": method, "url": url, "secured": secured,
                        "query": query, "body": body, "ctype": ctype,
                        "json_body": json_body})

    walk(coll.get("item")); return ops


def _api_operations(spec: dict, base: str, spec_src: str) -> list[dict]:
    if "item" in spec and "paths" not in spec:
        return _api_ops_postman(spec, base)
    ops: list[dict] = []; global_sec = spec.get("security")
    methods = ("get", "post", "put", "patch", "delete", "options", "head")
    for path, item in (spec.get("paths") or {}).items():
        item = _api_deref(spec, item) or {}
        common = [_api_deref(spec, p) for p in (item.get("parameters") or [])]
        for method in methods:
            op = item.get(method)
            if not isinstance(op, dict): continue
            params = common + [_api_deref(spec, p)
                               for p in (op.get("parameters") or [])]
            sec = op.get("security", global_sec)
            secured = bool(sec) and sec != [{}]
            filled = path; query: list[tuple[str, str]] = []
            for p in params:
                if not isinstance(p, dict) or not p.get("name"): continue
                schema = p.get("schema") or {
                    k: p[k] for k in ("type", "enum", "format") if k in p}
                val = _api_sample(spec, schema)
                if not isinstance(val, (str, int, float, bool)): val = "test"
                loc = p.get("in")
                if   loc == "path":  filled = filled.replace("{" + p["name"] + "}", str(val))
                elif loc == "query": query.append((p["name"], str(val)))
            rb = (_api_deref(spec, op.get("requestBody"))
                  if op.get("requestBody") else None)
            body = ctype = json_body = None
            if isinstance(rb, dict):
                content = rb.get("content") or {}
                if "application/json" in content:
                    sample = _api_sample(
                        spec, (content["application/json"] or {}).get("schema") or {})
                    body = json.dumps(sample).encode()
                    ctype = "application/json"; json_body = sample
                else:
                    for ct in ("application/x-www-form-urlencoded",
                               "multipart/form-data"):
                        if ct in content:
                            sample = _api_sample(
                                spec, (content[ct] or {}).get("schema") or {})
                            if isinstance(sample, dict):
                                body = urlencode(
                                    {k: v for k, v in sample.items()}).encode()
                                ctype = "application/x-www-form-urlencoded"
                                break
            url = base + (filled if filled.startswith("/") else "/" + filled)
            if query: url += ("&" if "?" in url else "?") + urlencode(query)
            ops.append({"method": method.upper(), "url": url,
                        "secured": secured, "query": query,
                        "body": body, "ctype": ctype, "json_body": json_body})
    return ops


# ── API engine ────────────────────────────────────────────────────────────────
def run_api(cfg: ApiConfig, out_dir: Path,
            log: Callable[[str], None],
            cancel: Optional[threading.Event] = None) -> tuple[dict, Path]:
    findings: list[dict] = []
    cancel   = cancel or threading.Event()
    stopped  = cancel.is_set
    throttle = _Throttle(cfg.rate_limit_rps)

    def add(sev, title, url, evidence="", cwe="", category="api"):
        findings.append({"severity": sev, "title": title, "url": url,
                         "evidence": (evidence or "")[:600],
                         "cwe": cwe, "category": category})

    def write_out(s: dict) -> Path:
        out = out_dir / "api.json"
        out.write_text(json.dumps(s, indent=2), encoding="utf-8"); return out

    opener, jar, hdrs = _make_opener(cfg)
    noauth = {"User-Agent": _DAST_UA, "Accept": "*/*"}
    spec = _api_load_spec(opener, hdrs, cfg, log)
    if not spec or not isinstance(spec, dict):
        add("high", "Could not load or parse the API spec",
            cfg.spec_source, "", "", "spec")
        s = {"target": "", "spec_source": cfg.spec_source,
             "profile": cfg.profile, "endpoints_total": 0,
             "endpoints_tested": 0, "cancelled": stopped(),
             "findings": findings}
        return s, write_out(s)

    base = _api_base_url(spec, cfg, cfg.spec_source.strip())
    if not base:
        add("medium", "No server/base URL found in spec",
            cfg.spec_source, "", "", "spec")
        s = {"target": "", "spec_source": cfg.spec_source,
             "profile": cfg.profile, "endpoints_total": 0,
             "endpoints_tested": 0, "cancelled": stopped(),
             "findings": findings}
        return s, write_out(s)
    if base.startswith("http://"):
        add("medium", "API served over plain HTTP", base,
            "Unencrypted.", "CWE-319", "transport")

    ops = _api_operations(spec, base, cfg.spec_source.strip())
    log(f"[api] base={base}  profile={cfg.profile}  operations={len(ops)}")
    excl_re = None
    if cfg.exclude_re:
        try: excl_re = _re.compile(cfg.exclude_re)
        except _re.error as e: log(f"[api] invalid exclude_re: {e}")

    def fetch(url, *, method="GET", data=None, req_hdrs=None, extra=None):
        throttle.wait()
        return _fetch(opener, req_hdrs if req_hdrs is not None else hdrs,
                      url, method=method, data=data,
                      timeout=cfg.timeout, extra=extra)

    workers = max(1, min(int(getattr(cfg, "concurrency", 6) or 1), 16))
    to_test = [op for op in ops
               if not (excl_re and excl_re.search(op["url"]))
               ][:cfg.max_endpoints]
    log(f"[api] testing {len(to_test)}/{len(ops)} endpoints  workers={workers}")

    _tl      = threading.local()
    _flock   = threading.Lock()
    passive_state = {"done": False}

    def add(sev, title, url, evidence="", cwe="", category="api"):   # noqa: F811
        with _flock:
            findings.append({"severity": sev, "title": title, "url": url,
                             "evidence": (evidence or "")[:600],
                             "cwe": cwe, "category": category})

    def wfetch(url, *, method="GET", data=None, req_hdrs=None, extra=None):
        o = getattr(_tl, "opener", None)
        if o is None:
            o = _clone_opener(cfg, jar); _tl.opener = o
        throttle.wait()
        return _fetch(o, req_hdrs if req_hdrs is not None else hdrs,
                      url, method=method, data=data,
                      timeout=cfg.timeout, extra=extra)

    def _do_passive(lower, fu, url):
        with _flock:
            if passive_state["done"]: return
            passive_state["done"] = True
        for hname, title, sev in _SEC_HEADERS:
            if hname not in lower:
                add(sev, title, fu,
                    f"Headers: {sorted(lower.keys())}", "CWE-693", "headers")
        _passive_header_findings(lower, fu, add)
        try:
            sto, hho, _, _ = wfetch(url.split("?", 1)[0], method="OPTIONS")
            allow = ""
            for k, v in (hho or {}).items():
                if k.lower() in ("allow", "access-control-allow-methods"):
                    allow = (allow + "," + v) if allow else v
            risky = [m for m in ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT")
                     if m in allow.upper()]
            if risky:
                add("low",
                    f"State-changing HTTP methods advertised: {', '.join(risky)}",
                    fu, f"Allow: {allow}", "CWE-650", "methods")
        except Exception:
            pass

    def _test_op(op):
        if stopped(): return
        url, method = op["url"], op["method"]
        extra = {"Content-Type": op["ctype"]} if op["ctype"] else None
        st, hh2, bb, fu = wfetch(url, method=method, data=op["body"],
                                  extra=extra)
        log(f"[api] {st} {method} {url}")
        if st == 0: return
        lower = {k.lower(): v for k, v in hh2.items()}

        if not passive_state["done"] and 200 <= st < 500:
            _do_passive(lower, fu, url)

        if (op["secured"] and cfg.auth_type in ("basic", "bearer", "header")
                and 200 <= st < 300):
            st2, _, _, _ = wfetch(url, method=method, data=op["body"],
                                   req_hdrs=noauth, extra=extra)
            if st2 and 200 <= st2 < 300:
                add("critical", f"Auth bypass on {method} {url}", fu,
                    f"Without auth returned HTTP {st2}.", "CWE-287", "auth")

        if op["query"]:
            qk, _ = op["query"][0]
            bad = op["url"].replace(f"{qk}=", f"{qk}=%00%27%22", 1)
            st3, _, bb3, _ = wfetch(bad, method=method)
            if st3 >= 500 and bb3:
                low_b = bb3.decode("utf-8", errors="replace").lower()
                if any(m in low_b for m in ("traceback", "stack trace",
                                            "exception", "at java.",
                                            "syntaxerror")):
                    add("medium", f"Stack trace exposed on {method}", bad,
                        "Malformed input triggered internal error.",
                        "CWE-209", "errors")

        if cfg.profile == "active":
            for idx, (qk, _qv) in enumerate(op["query"]):
                if stopped(): break
                base_qs = list(op["query"])
                xss = base_qs[:]; xss[idx] = (qk, _XSS_PROBE)
                xurl = op["url"].split("?", 1)[0] + "?" + urlencode(xss)
                stx, _, bbx, _ = wfetch(xurl, method=method,
                                         data=op["body"], extra=extra)
                if stx and bbx and _XSS_PROBE in bbx.decode("utf-8", errors="replace"):
                    add("high", f"Reflected XSS in query param '{qk}'", xurl,
                        "Payload reflected.", "CWE-79", "xss")
                sqi = base_qs[:]; sqi[idx] = (qk, str(_qv) + "'\"")
                surl = op["url"].split("?", 1)[0] + "?" + urlencode(sqi)
                sts, _, bbs, _ = wfetch(surl, method=method,
                                         data=op["body"], extra=extra)
                if sts and bbs:
                    low_s = bbs.decode("utf-8", errors="replace").lower()
                    hit = next((e for e in _SQL_ERRORS if e in low_s), None)
                    if hit:
                        add("critical", f"SQLi in param '{qk}'", surl,
                            f"DB error: {hit!r}", "CWE-89", "sqli")
                if qk.lower() in _API_REDIRECT:
                    rq = base_qs[:]; rq[idx] = (qk, "https://example.com/")
                    rurl = op["url"].split("?", 1)[0] + "?" + urlencode(rq)
                    str_, rh, _, _ = wfetch(rurl, method=method)
                    loc = rh.get("Location") or rh.get("location") or ""
                    if (str_ in (301, 302, 303, 307, 308)
                            and loc.startswith("https://example.com")):
                        add("high", f"Open redirect via '{qk}'", rurl,
                            f"Location: {loc}", "CWE-601", "redirect")
            if isinstance(op["json_body"], dict):
                for k, v in list(op["json_body"].items()):
                    if not isinstance(v, str) or stopped(): continue
                    mutated = dict(op["json_body"]); mutated[k] = _XSS_PROBE
                    stx, _, bbx, _ = wfetch(url, method=method,
                                             data=json.dumps(mutated).encode(),
                                             extra=extra)
                    if stx and bbx and _XSS_PROBE in bbx.decode("utf-8", errors="replace"):
                        add("high", f"Reflected XSS in JSON body field '{k}'",
                            url, "Payload reflected.", "CWE-79", "xss")

    if workers > 1 and len(to_test) > 1:
        with ThreadPoolExecutor(max_workers=workers) as ex_:
            list(ex_.map(_test_op, to_test))
    else:
        for op in to_test:
            if stopped(): break
            _test_op(op)
    tested = len(to_test)

    findings.sort(key=lambda x: -_DAST_SVR.get(x["severity"], 0))
    s = {"target": base, "spec_source": cfg.spec_source,
         "profile": cfg.profile,
         "endpoints_total": len(ops), "endpoints_tested": tested,
         "cancelled": stopped(), "findings": findings}
    if stopped(): log("[api] scan cancelled")
    out_p = write_out(s)
    log(f"[api] complete: {tested}/{len(ops)} endpoints, "
        f"{len(findings)} findings → {out_p}")
    return s, out_p
