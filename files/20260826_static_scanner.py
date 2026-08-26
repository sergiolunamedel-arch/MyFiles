"""static_scanner.py — unified Static-analysis engine + its GUI tab."""

from __future__ import annotations

import json, os, re, sys, shutil, subprocess, platform, tempfile, time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

IS_WIN   = os.name == "nt"
IS_MAC   = sys.platform == "darwin"
IS_LINUX = not IS_WIN and not IS_MAC

def _augment_path() -> None:
    """The process PATH at launch is often stale or minimal (desktop launcher, a terminal opened before an installer…"""
    if IS_WIN:
        candidates = []
        local = os.environ.get("LOCALAPPDATA")
        if local:

            candidates += [str(Path(local) / "snyk"), str(Path(local) / "snyk" / "bin")]
        appdata = os.environ.get("APPDATA")
        if appdata:

            candidates.append(str(Path(appdata) / "npm"))
        cur = os.environ.get("PATH", "")
        parts = cur.split(os.pathsep)
        extra = [c for c in candidates if c and c not in parts and os.path.isdir(c)]
        if extra:
            os.environ["PATH"] = os.pathsep.join(extra + parts)
        return
    home = Path.home()
    candidates = [
        "/opt/homebrew/bin", "/opt/homebrew/sbin",
        "/usr/local/bin", "/usr/local/sbin",
        str(home / ".local" / "bin"), str(home / "bin"),
        "/opt/local/bin",
        str(home / ".nvm" / "current" / "bin"),
    ]
    cur = os.environ.get("PATH", "")
    parts = cur.split(os.pathsep)
    extra = [c for c in candidates if c and c not in parts and os.path.isdir(c)]
    if extra:
        os.environ["PATH"] = os.pathsep.join(extra + parts)

_augment_path()

def _which(cmd: str) -> Optional[str]:
    if (f := shutil.which(cmd)):
        return f
    if os.name == "nt":
        for ext in (".cmd", ".bat", ".exe"):
            if (f := shutil.which(cmd + ext)):
                return f
    return None

_NOWIN = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WIN else {}

def _run(args, cwd=None, env=None, timeout=600) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, cwd=str(cwd) if cwd else None,
        env=env if env is not None else os.environ.copy(),
        timeout=timeout, capture_output=True, text=True,
        encoding="utf-8", errors="replace", shell=False, **_NOWIN)

_TLS_ERROR_MARKERS = (
    "self-signed certificate", "self signed certificate", "self_signed_cert",
    "unable to verify", "unable to get local issuer", "cert_in_chain",
    "cert_has_expired", "err_tls", "certificate chain", "econnreset",
    "tunneling socket", "depth_zero_self_signed", "ssl",
)

def _looks_like_tls_error(text: str) -> bool:
    low = (text or "").lower()
    return any(m in low for m in _TLS_ERROR_MARKERS)

_AUTH_ERROR_MARKERS = (
    "use `snyk auth`", "use 'snyk auth'", "snyk auth` to authenticate",
    "snyk auth' to authenticate", "not authenticated", "must be authenticated",
    "authentication error", "unauthorized", "token is invalid",
    "invalid auth", "re-authenticate", "401",
)

def _looks_like_auth_error(text: str) -> bool:
    low = (text or "").lower()
    return any(m in low for m in _AUTH_ERROR_MARKERS)

def _find_ca_bundle() -> Optional[str]:
    """Locate a corporate CA bundle the user (or their MDM/IT) may already have configured, so we can verify the prox…"""
    for var in ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
                "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SNYK_CA_BUNDLE"):
        p = os.environ.get(var)
        if p and Path(p).is_file() and Path(p).stat().st_size > 0:
            return p
    return None

def _export_windows_ca_bundle(log: Callable[[str], None]) -> Optional[str]:
    """On Windows, the corporate root/intermediate CA almost always lives in the system certificate store (pushed by…"""
    if not IS_WIN:
        return None
    out = Path(tempfile.gettempdir()) / "bbscanner_corp_ca.pem"
    if out.exists() and out.stat().st_size > 0:
        return str(out)

    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$o=@();"
        "foreach($s in 'Root','CA'){"
        "  Get-ChildItem \"Cert:\\LocalMachine\\$s\" | ForEach-Object {"
        "    $b=[Convert]::ToBase64String($_.RawData,'InsertLineBreaks');"
        "    $o+=\"-----BEGIN CERTIFICATE-----`n$b`n-----END CERTIFICATE-----\"}};"
        f"$o -join \"`n\" | Out-File -FilePath '{out}' -Encoding ascii"
    )
    try:
        r = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                 timeout=120)
        if out.exists() and out.stat().st_size > 0 and "BEGIN CERTIFICATE" in\
                out.read_text(encoding="ascii", errors="ignore"):
            log(f"[tls] exported Windows cert store → {out}")
            return str(out)
        if r.stderr:
            log(f"[tls] could not export Windows cert store: {r.stderr.strip()[:200]}")
    except Exception as e:
        log(f"[tls] cert-store export failed: {e!r}")
    return None

def _run_tls(args, cwd=None, timeout=900,
             log: Callable[[str], None] = lambda _: None) -> subprocess.CompletedProcess:
    """Run a Node/Snyk command, retrying through a corporate TLS-inspecting proxy: first with a discovered/exported C…"""
    env = os.environ.copy()
    log(f"$ {' '.join(args)}")
    r = _run(args, cwd=cwd, env=env, timeout=timeout)
    combined = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0 and _looks_like_tls_error(combined):
        ca = _find_ca_bundle() or _export_windows_ca_bundle(log)
        if ca:
            log(f"[tls-retry] retrying with NODE_EXTRA_CA_CERTS={ca}")
            env2 = os.environ.copy(); env2["NODE_EXTRA_CA_CERTS"] = ca
            r = _run(args, cwd=cwd, env=env2, timeout=timeout)
            if r.returncode == 0 or not _looks_like_tls_error((r.stdout or "") + (r.stderr or "")):
                return r
        log("[tls-retry] CA bundle unavailable/insufficient — retrying with "
            "TLS verification DISABLED (NODE_TLS_REJECT_UNAUTHORIZED=0). "
            "This is a local workaround for the proxy cert only.")
        env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
        r = _run(args, cwd=cwd, env=env, timeout=timeout)
    return r

_TLS_ENV_READY = False

def setup_proxy_tls_env(log: Callable[[str], None] = lambda _: None,
                        prefer_insecure: bool = False) -> str:
    """Configure os.environ so Node/Snyk can talk through a corporate proxy."""
    global _TLS_ENV_READY

    if not prefer_insecure:
        if os.environ.get("NODE_TLS_REJECT_UNAUTHORIZED") == "0":
            _TLS_ENV_READY = True; return "preset"
        if os.environ.get("NODE_EXTRA_CA_CERTS") and\
                Path(os.environ["NODE_EXTRA_CA_CERTS"]).is_file():
            _TLS_ENV_READY = True; return "preset"
        ca = _find_ca_bundle() or _export_windows_ca_bundle(log)
        if ca:
            os.environ["NODE_EXTRA_CA_CERTS"] = ca
            log(f"[tls] trusting corporate proxy via NODE_EXTRA_CA_CERTS={ca}")
            _TLS_ENV_READY = True; return "ca-bundle"

    os.environ["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
    os.environ.pop("NODE_EXTRA_CA_CERTS", None)
    log("[tls] disabling Node TLS verification (NODE_TLS_REJECT_UNAUTHORIZED=0) "
        "so the Snyk CLI can run behind the proxy. Scoped to this app's child "
        "processes; set NODE_EXTRA_CA_CERTS to your company CA for the secure "
        "alternative.")
    _TLS_ENV_READY = True
    return "insecure"

_SNYK_WORKS_CACHE: tuple[bool, str] | None = None
_SNYK_WORKS_CACHE_AT: float = 0.0
_SNYK_WORKS_CACHE_TTL: float = 300.0

def _snyk_works(timeout: int = 90) -> tuple[bool, str]:
    """True iff `snyk --version` actually returns a version — i.e. the binary exists AND can start (the wrapper's one…"""
    global _SNYK_WORKS_CACHE, _SNYK_WORKS_CACHE_AT
    now = time.time()
    if _SNYK_WORKS_CACHE is not None and (now - _SNYK_WORKS_CACHE_AT) < _SNYK_WORKS_CACHE_TTL:
        return _SNYK_WORKS_CACHE
    sb = _which("snyk")
    if not sb:
        result = False, "Snyk CLI not found on PATH"
        _SNYK_WORKS_CACHE, _SNYK_WORKS_CACHE_AT = result, now
        return result
    try:
        r = _run([sb, "--version"], timeout=timeout)
        if r.returncode == 0 and re.search(r"\d+\.\d+\.\d+", r.stdout or ""):
            result = True, (r.stdout or "").strip().splitlines()[0][:60]
        else:
            detail = ((r.stdout or "") + (r.stderr or "")).strip()
            result = False, detail[:300] or f"exit code {r.returncode}"
    except Exception as e:
        result = False, repr(e)

    if result[0]:
        _SNYK_WORKS_CACHE, _SNYK_WORKS_CACHE_AT = result, now
    return result

def ensure_snyk_ready(log: Callable[[str], None]) -> bool:
    """Guarantee a *runnable* Snyk CLI, repairing the common corporate failure where the npm wrapper is installed but…"""
    ok, detail = _snyk_works(timeout=30)
    if ok:
        log(f"[snyk] CLI ready ({detail})")
        return True
    log(f"[snyk] CLI present but not runnable yet: {detail}")

    mode = setup_proxy_tls_env(log)
    ok, detail = _snyk_works(timeout=180)
    if ok:
        log(f"[snyk] CLI ready after TLS setup [{mode}] ({detail})")
        return True

    if mode == "ca-bundle":
        setup_proxy_tls_env(log, prefer_insecure=True)
        ok, detail = _snyk_works(timeout=180)
        if ok:
            log(f"[snyk] CLI ready after disabling TLS verification ({detail})")
            return True

    log("[snyk] repairing by installing the standalone Snyk binary "
        "(bypasses the npm wrapper's blocked download)…")
    if _install_standalone_snyk(log):
        ok, detail = _snyk_works(timeout=180)
        if ok:
            log(f"[snyk] standalone CLI ready ({detail})")
            return True
        log(f"[snyk] standalone CLI still not runnable: {detail}")
    log("[snyk] could not get a runnable Snyk CLI automatically. If your "
        "network uses a TLS-inspecting proxy, ask IT for the root CA .pem and "
        "set NODE_EXTRA_CA_CERTS to it, then retry.")
    return False

def _brew() -> Optional[str]:
    """Locate Homebrew even when it's not on the (possibly minimal) PATH."""
    if p := shutil.which("brew"):
        return p
    for cand in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew"):
        if Path(cand).exists():
            return cand
    return None

def _snyk_bin() -> str:
    """Resolved snyk executable (snyk.cmd on Windows), falling back to 'snyk'."""
    return _which("snyk") or "snyk"

def _linux_pkg_mgr() -> Optional[tuple[str, list[str]]]:
    """Return (manager, install-prefix-args) for the host Linux distro."""
    if shutil.which("apt-get"):
        return "apt-get", ["apt-get", "install", "-y"]
    if shutil.which("dnf"):
        return "dnf", ["dnf", "install", "-y"]
    if shutil.which("yum"):
        return "yum", ["yum", "install", "-y"]
    if shutil.which("zypper"):
        return "zypper", ["zypper", "--non-interactive", "install"]
    if shutil.which("pacman"):
        return "pacman", ["pacman", "-S", "--noconfirm"]
    return None

def _sudo_prefix() -> list[str]:
    """Non-interactive sudo prefix when needed and available, else empty."""
    if os.geteuid() == 0 if hasattr(os, "geteuid") else False:
        return []
    if shutil.which("sudo"):
        return ["sudo", "-n"]
    return []

def _download_file(url: str, dest: Path, log: Callable[[str], None],
                   timeout: int = 120) -> bool:
    """GET `url` to `dest`."""
    import ssl, urllib.error, urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "vuln-scanner/1.0"})
    try:
        log(f"[download] {url}")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLCertVerificationError):
                log(f"[download] TLS verify failed ({e.reason}); "
                    f"retrying without cert verification (fixed host only)…")
                ctx = ssl._create_unverified_context()
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    data = resp.read()
            else:
                raise
        if not data:
            log("[download] empty response"); return False
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        log(f"[download] saved {len(data)//1024} KB → {dest}")
        return True
    except Exception as e:
        log(f"[download] failed: {e!r}")
        return False

def _standalone_snyk_asset() -> Optional[str]:
    """Asset name for Snyk's npm-free standalone CLI binary for this host."""
    arch = (platform.machine() or "").lower()
    is_arm = arch in ("arm64", "aarch64")
    if IS_WIN:
        return "snyk-win.exe"
    if IS_MAC:
        return "snyk-macos-arm64" if is_arm else "snyk-macos"

    if Path("/etc/alpine-release").exists():
        return "snyk-alpine-arm64" if is_arm else "snyk-alpine"
    return "snyk-linux-arm64" if is_arm else "snyk-linux"

def _standalone_snyk_paths() -> Optional[tuple[Path, Path]]:
    """(bindir, target) for the npm-free standalone CLI binary on this host, or None
    if this platform/arch has no published standalone asset."""
    asset = _standalone_snyk_asset()
    if not asset:
        return None
    if IS_WIN:
        bindir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "snyk" / "bin"
        target = bindir / "snyk.exe"
    else:
        bindir = Path.home() / ".local" / "bin"
        target = bindir / "snyk"
    return bindir, target

def _install_standalone_snyk(log: Callable[[str], None]) -> bool:
    """Universal npm-free fallback: download the official Snyk CLI binary to ~/.local/bin (or %LOCALAPPDATA% on Windo…"""
    paths = _standalone_snyk_paths()
    if not paths:
        return False
    bindir, target = paths
    asset = _standalone_snyk_asset()
    if target.exists() and target.stat().st_size > 1024:
        log(f"[snyk] standalone CLI already cached → {target} "
            f"(use 'Reinstalar Snyk (limpio)' to force a fresh download of the latest release)")
        os.environ["PATH"] = str(bindir) + os.pathsep + os.environ.get("PATH", "")
        return True
    url = f"https://static.snyk.io/cli/latest/{asset}"
    log(f"[snyk] installing standalone CLI ({asset})…")
    if not _download_file(url, target, log, timeout=180):
        return False
    if not IS_WIN:
        try: os.chmod(target, 0o755)
        except Exception: pass

    os.environ["PATH"] = str(bindir) + os.pathsep + os.environ.get("PATH", "")
    if _which("snyk"):
        log(f"[snyk] standalone CLI ready → {target}")
        return True
    log(f"[snyk] installed to {target}, but {bindir} is not on PATH. "
        f"Add it to your shell profile (e.g. export PATH=\"{bindir}:$PATH\").")
    return target.exists()

@dataclass
class CheckResult:
    name: str; ok: bool; detail: str = ""; fixable: bool = False

def check_python() -> CheckResult:
    v = sys.version_info
    return CheckResult("Python ≥ 3.9",
                       (v.major, v.minor) >= (3, 9),
                       f"Python {v.major}.{v.minor}.{v.micro}")

def _check_tool(label: str, cmd: str) -> CheckResult:
    resolved = _which(cmd)
    if not resolved:
        return CheckResult(label, False, "not found in PATH", fixable=True)
    try:
        r = _run([resolved, "--version"])
        return CheckResult(label, r.returncode == 0,
                           (r.stdout or "").strip(), fixable=True)
    except Exception as e:
        return CheckResult(label, False, str(e), fixable=True)

def check_node() -> CheckResult: return _check_tool("Node.js", "node")
def check_npm()  -> CheckResult: return _check_tool("npm", "npm")

def tool_present(cmd: str) -> bool:
    """Cheap presence-only check: a PATH lookup, no subprocess spawn."""
    return _which(cmd) is not None

def check_snyk() -> CheckResult:
    """Snyk is only 'OK' if it actually RUNS."""
    if not _which("snyk"):
        return CheckResult("Snyk CLI", False, "not found in PATH", fixable=True)
    ok, detail = _snyk_works(timeout=30)
    if ok:
        return CheckResult("Snyk CLI", True, detail, fixable=True)
    if _looks_like_tls_error(detail) or "download" in detail.lower()\
            or "ENOENT" in detail or "exit code" in detail:
        return CheckResult("Snyk CLI", False,
                           "present but can't start (proxy/cert blocks its "
                           "download) — click Fix", fixable=True)
    return CheckResult("Snyk CLI", False, detail[:120], fixable=True)

def _latest_snyk_version(log: Callable[[str], None] = lambda *_: None) -> Optional[str]:
    """Latest published Snyk CLI version per the npm registry -- the only source this
    app can check without guessing at an undocumented endpoint. Returns None if npm
    or the registry isn't reachable (callers must treat that as 'can't tell', not
    'outdated'). Pre-warms the same corporate-proxy TLS setup Snyk's own CLI calls use
    (setup_proxy_tls_env) before asking npm to reach the registry over HTTPS -- npm is
    also a Node process subject to the same TLS-inspecting proxy, and unlike
    check_node()/check_npm() (which only run `--version` locally, no network at all)
    this call actually needs to get through it. Only runs at most once every
    _VERSION_CHECK_INTERVAL (see check_snyk_version_current), so the occasional extra
    couple of seconds this adds is a fair trade for actually succeeding instead of
    just failing fast and never learning the real version."""
    if not _which("npm"):
        return None
    setup_proxy_tls_env(log)
    npm = "npm.cmd" if IS_WIN else "npm"
    try:
        r = _run([npm, "view", "snyk", "version"], timeout=15)
        v = (r.stdout or "").strip()
        if re.match(r"^\d+\.\d+\.\d+", v):
            return v
    except Exception as e:
        log(f"[snyk] could not query latest version via npm: {e!r}")
    return None

def _parse_semver(v: str) -> tuple:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", v or "")
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)

_VERSION_CHECK_CACHE = Path(tempfile.gettempdir()) / "bbscanner_snyk_version_check.json"
_VERSION_CHECK_INTERVAL = 7 * 24 * 3600  # once a week, per explicit request

def check_snyk_version_current(log: Callable[[str], None] = lambda *_: None,
                               *, force: bool = False) -> tuple[bool, str]:
    """(is_current, detail). Compares installed vs npm's registry, throttled to once
    every 7 days via a temp-dir cache (not DATA_DIR -- this can run before this
    module's globals are wired from the main app). On the other ~6 days this returns
    the cached result without touching the network at all -- callers that just need
    "is Snyk installed" should use check_snyk()/tool_present() instead, not this one.
    Pass force=True to bypass the cache (e.g. a user-triggered check)."""
    now = time.time()
    if not force and _VERSION_CHECK_CACHE.exists():
        try:
            cached = json.loads(_VERSION_CHECK_CACHE.read_text(encoding="utf-8"))
            if (now - cached.get("checked_at", 0)) < _VERSION_CHECK_INTERVAL:
                return bool(cached.get("is_current", True)), cached.get("detail", "cached")
        except Exception:
            pass

    ok, installed_detail = _snyk_works(timeout=10)
    if not ok:
        return True, "snyk not runnable — nothing to compare (let the normal repair path handle it)"
    installed_m = re.search(r"(\d+\.\d+\.\d+)", installed_detail)
    installed = installed_m.group(1) if installed_m else ""
    latest = _latest_snyk_version(log)
    if not latest or not installed:
        return True, "could not determine the latest version (offline or no npm) — skipping check"

    is_current = _parse_semver(installed) >= _parse_semver(latest)
    detail = f"installed {installed}, latest {latest}"
    try:
        _VERSION_CHECK_CACHE.write_text(
            json.dumps({"checked_at": now, "is_current": is_current, "detail": detail}),
            encoding="utf-8")
    except Exception:
        pass
    return is_current, detail

_CFG_FILE_SEARCHED: bool = False
_CFG_FILE_PATH:     str  = ""
_CFG_CACHE:         dict = {}
_CFG_CACHE_MTIME:   float = 0.0

def _snyk_configstore_path() -> str:
    """Locate Snyk's configstore JSON without running the CLI (one-time search)."""
    global _CFG_FILE_SEARCHED, _CFG_FILE_PATH
    if _CFG_FILE_SEARCHED:
        return _CFG_FILE_PATH
    _CFG_FILE_SEARCHED = True
    candidates: list[Path] = []
    if sys.platform == "win32":
        for env_key in ("APPDATA", "LOCALAPPDATA"):
            base = os.environ.get(env_key, "")
            if base:
                candidates.append(Path(base) / "configstore" / "snyk.json")
    home = Path.home()
    candidates += [
        home / ".config" / "configstore" / "snyk.json",
        home / ".snyk" / "config.json",
    ]
    for p in candidates:
        try:
            if p.exists():
                _CFG_FILE_PATH = str(p)
                return _CFG_FILE_PATH
        except Exception:
            continue
    _CFG_FILE_PATH = ""
    return ""

def _snyk_cfg_from_file(key: str) -> str | None:
    """Read a config key from the Snyk JSON file."""
    global _CFG_CACHE, _CFG_CACHE_MTIME
    try:
        path = _snyk_configstore_path()
        if not path:
            return None
        mtime = os.path.getmtime(path)
        if not _CFG_CACHE or abs(mtime - _CFG_CACHE_MTIME) > 0.01:
            _CFG_CACHE      = json.loads(Path(path).read_text(encoding="utf-8"))
            _CFG_CACHE_MTIME = mtime
        v = _CFG_CACHE.get(key)
        if v is None:
            return None
        sv = str(v)
        if sv.lower() in ("", "undefined", "null", "not set"):
            return None
        return sv
    except Exception:
        return None

def _snyk_cfg(key: str) -> str:

    fast = _snyk_cfg_from_file(key)
    if fast is not None:
        return fast

    try:
        v = (_run([_snyk_bin(), "config", "get", key]).stdout or "").strip()
        return "" if v.lower() in ("", "undefined", "null", "not set") else v
    except Exception:
        return ""

def _snyk_cred_kind() -> str:
    """What credential is configured locally (for labelling only)."""

    if _snyk_cfg("api"):
        return "token"
    if _snyk_cfg("INTERNAL_OAUTH_TOKEN_STORAGE") or _snyk_cfg("oauth_token"):
        return "SSO/OAuth"
    return ""

def _extract_access_token(val) -> str:
    """Pull the bearer access token out of a Snyk OAuth credential."""
    if not val:
        return ""
    if isinstance(val, dict):
        return str(val.get("access_token") or val.get("token") or "").strip()
    s = str(val).strip()
    if s.startswith("{"):
        try:
            d = json.loads(s)
            return str(d.get("access_token") or d.get("token") or "").strip()
        except Exception:
            return ""
    return s

def get_snyk_token(log: Callable[[str], None] = lambda *_: None) -> str:
    """Return the Snyk credential to REUSE for Snyk API & Web (Probely) scans."""

    val = None
    try:
        path = _snyk_configstore_path()
        if path:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            val = data.get("INTERNAL_OAUTH_TOKEN_STORAGE")
    except Exception:
        val = None
    if val is None:
        val = _snyk_cfg("INTERNAL_OAUTH_TOKEN_STORAGE") or None
    tok = _extract_access_token(val)
    if tok:
        return tok
    for key in ("oauth_token", "api"):
        v = _snyk_cfg(key)
        if v:
            return v.strip()
    return ""

def get_snyk_auth_scheme() -> str:
    """HTTP Authorization scheme matching the reused credential."""
    if _snyk_cfg("INTERNAL_OAUTH_TOKEN_STORAGE") or _snyk_cfg("oauth_token"):
        return "Bearer"
    return "JWT"

_PROBELY_KEY: str = ""

def set_probely_key(key: str) -> None:
    """Set the in-process Probely API key (called by the GUI from settings or after the user pastes/validates a key)."""
    global _PROBELY_KEY
    _PROBELY_KEY = (key or "").strip()

def get_probely_key() -> str:
    """Return the user's Probely API key, or '' if none is configured."""
    return _PROBELY_KEY

def get_probely_auth_scheme() -> str:
    """Probely API keys are always sent as 'Authorization: JWT <key>'."""
    return "JWT"

def check_auth() -> CheckResult:
    """Report whether a Snyk credential is configured locally."""
    if not _which("snyk"):
        return CheckResult("Snyk auth", False, "Snyk CLI missing", fixable=True)
    kind = _snyk_cred_kind()
    if kind:
        return CheckResult("Snyk auth", True, f"{kind} configured", fixable=True)
    return CheckResult("Snyk auth", False, "not authenticated", fixable=True)

def clear_snyk_credentials(log: Callable[[str], None]) -> None:
    """Remove any locally-stored Snyk credential so the next `snyk auth` starts clean."""
    _CRED_KEYS = ("api", "INTERNAL_OAUTH_TOKEN_STORAGE", "oauth_token")
    path = _snyk_configstore_path()
    if path:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            changed = False
            for key in _CRED_KEYS:
                if key in data:
                    del data[key]
                    changed = True
            if changed:
                Path(path).write_text(
                    json.dumps(data, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )

                global _CFG_CACHE, _CFG_CACHE_MTIME
                _CFG_CACHE = {}
                _CFG_CACHE_MTIME = 0.0
            log("[auth] cleared stored Snyk credentials (direct file update) — "
                "starting a fresh sign-in through your organization's SSO.")
            return
        except Exception as exc:
            log(f"[auth] direct file clear failed ({exc!r}), falling back to CLI.")

    for key in _CRED_KEYS:
        try:
            _run([_snyk_bin(), "config", "unset", key], timeout=20)
        except Exception:
            pass
    log("[auth] cleared stored Snyk credentials — starting a fresh sign-in "
        "through your organization's SSO.")

def install_node(log: Callable[[str], None]) -> bool:
    if _which("node") and _which("npm"):
        log("[node] already installed"); return True

    if IS_WIN:
        if not _which("winget"):
            log("[node] install Node.js LTS from https://nodejs.org/"); return False
        log("[node] installing via winget (source: winget, not msstore)…")
        r = _run(["winget", "install", "--id", "OpenJS.NodeJS.LTS", "-e",
                  "--source", "winget", "--silent", "--accept-package-agreements",
                  "--accept-source-agreements"], timeout=1800)
        log((r.stdout or "") + (r.stderr or ""))
        return r.returncode == 0

    if IS_MAC:
        brew = _brew()
        if not brew:
            log("[node] Homebrew not found. Install it from https://brew.sh "
                "then re-run, or install Node.js LTS from https://nodejs.org/.")
            return False
        log("[node] installing via Homebrew (brew install node)…")
        r = _run([brew, "install", "node"], timeout=1800)
        if r.stdout: log(r.stdout.strip()[-2000:])
        if r.stderr: log(r.stderr.strip()[-2000:])
        _augment_path()
        return _which("node") is not None and _which("npm") is not None

    mgr = _linux_pkg_mgr()
    if not mgr:
        log("[node] no supported package manager found. Install Node.js LTS via "
            "your distro or nvm (https://github.com/nvm-sh/nvm).")
        return False
    name, install_args = mgr

    pkgs = ["nodejs", "npm"] if name in ("apt-get", "dnf", "yum") else ["nodejs", "npm"]
    sudo = _sudo_prefix()
    if name == "apt-get":
        log("[node] apt-get update…")
        _run(sudo + ["apt-get", "update"], timeout=600)
    log(f"[node] installing via {name} ({' '.join(pkgs)})…")
    r = _run(sudo + install_args + pkgs, timeout=1800)
    if r.stdout: log(r.stdout.strip()[-2000:])
    if r.stderr: log(r.stderr.strip()[-2000:])
    if r.returncode != 0 and sudo and "-n" in sudo:
        log("[node] automatic install needs elevated rights. Run manually:\n"
            f"    sudo {' '.join(install_args + pkgs)}")
    _augment_path()
    return _which("node") is not None and _which("npm") is not None

def install_snyk(log: Callable[[str], None], *, force: bool = False) -> bool:

    setup_proxy_tls_env(log)

    if _which("snyk") and not force:
        ok, _ = _snyk_works(timeout=30)
        if ok:
            log("[snyk] already installed and runnable"); return True
        log("[snyk] found on PATH but not runnable — repairing…")
        if ensure_snyk_ready(log):
            return True
        log("[snyk] repair did not succeed; attempting a fresh install…")
    elif _which("snyk") and force:
        log(f"[snyk] force-reinstall: 'snyk' is still resolvable on PATH "
            f"({_which('snyk')}) — a previous uninstall step may have missed it "
            f"(e.g. an install method this app doesn't manage). Installing fresh "
            f"anyway rather than trusting it.")

    if _which("npm"):
        npm = "npm.cmd" if IS_WIN else "npm"
        log("[snyk] npm install -g snyk")
        r = _run_tls([npm, "install", "-g", "snyk"], log=log, timeout=1800)
        if r.stdout: log(r.stdout)
        if r.stderr: log(r.stderr)
        _augment_path()
        if _which("snyk") and ensure_snyk_ready(log):
            return True
        log("[snyk] npm install did not yield a runnable 'snyk'; trying fallback…")

    if IS_MAC and _brew():
        brew = _brew()
        log("[snyk] installing via Homebrew (brew install snyk-cli)…")
        r = _run([brew, "install", "snyk-cli"], timeout=1800)
        if r.returncode != 0:
            r = _run([brew, "install", "snyk"], timeout=1800)
        if r.stdout: log(r.stdout.strip()[-2000:])
        if r.stderr: log(r.stderr.strip()[-2000:])
        _augment_path()
        if _which("snyk") and ensure_snyk_ready(log):
            return True

    if IS_WIN and _which("winget"):
        log("[snyk] installing via winget (Snyk.SnykCLI, source: winget, not msstore)…")
        r = _run(["winget", "install", "--id", "Snyk.SnykCLI", "-e",
                  "--source", "winget", "--silent",
                  "--accept-package-agreements", "--accept-source-agreements"],
                 timeout=1800)
        log((r.stdout or "") + (r.stderr or ""))
        _augment_path()
        if _which("snyk") and ensure_snyk_ready(log):
            return True

    log("[snyk] falling back to the standalone Snyk CLI binary…")
    if _install_standalone_snyk(log):
        return ensure_snyk_ready(log)
    return False

def _scoop_root() -> Path:
    return Path(os.environ.get("SCOOP") or (Path.home() / "scoop"))

def _uninstall_snyk_binary(log: Callable[[str], None]) -> None:
    """Best-effort removal of every existing Snyk CLI install this app knows how to
    create (npm global, standalone binary, winget, brew) so the next install() call
    downloads a genuinely fresh copy instead of silently reusing whatever is cached —
    the standalone path in particular caches its binary forever otherwise (see
    _install_standalone_snyk)."""
    if _which("npm"):
        npm = "npm.cmd" if IS_WIN else "npm"
        try:
            log("[snyk] npm uninstall -g snyk")
            r = _run([npm, "uninstall", "-g", "snyk"], timeout=300)
            if r.stdout: log(r.stdout.strip()[-800:])
            if r.stderr: log(r.stderr.strip()[-800:])
        except Exception as e:
            log(f"[snyk] npm uninstall skipped: {e!r}")

    paths = _standalone_snyk_paths()
    if paths:
        _, target = paths
        try:
            if target.exists():
                target.unlink()
                log(f"[snyk] removed cached standalone binary: {target}")
        except Exception as e:
            log(f"[snyk] could not remove {target}: {e!r}")

    if IS_MAC and _brew():
        brew = _brew()
        try:
            _run([brew, "uninstall", "snyk-cli"], timeout=300)
            _run([brew, "uninstall", "snyk"], timeout=300)
        except Exception:
            pass

    if IS_WIN and _which("winget"):
        try:
            # Must match the --source winget used by the install side (see
            # install_node/install_snyk) -- without it, winget's default
            # "search every configured source" behavior includes msstore, which
            # this corporate environment can't reach. That failed msstore lookup
            # was showing up raw in the boot log ("Error al buscar en el origen...
            # msstore" / "No se encontró ningún paquete...") right at this step,
            # and could also make winget report no match at all for a package
            # that IS present via the winget source, silently no-op'ing this
            # uninstall.
            r = _run(["winget", "uninstall", "--id", "Snyk.SnykCLI", "-e",
                      "--source", "winget", "--silent"],
                     timeout=300)
            if r.stdout: log(r.stdout.strip()[-500:])
            if r.stderr: log(r.stderr.strip()[-500:])
        except Exception:
            pass

    if IS_WIN:
        # Scoop is a common corporate-desktop Windows package manager NOT covered by
        # any of the branches above — its "snyk" bucket manifest can lag well behind
        # the official npm/standalone releases. If `scoop` itself is invokable, do a
        # real uninstall (removes the versioned app dir, not just the shim); either
        # way, also remove the shim file directly, since a lingering shim earlier on
        # PATH than a freshly-installed copy would keep shadowing it invisibly.
        scoop_cmd = _which("scoop")
        if scoop_cmd:
            try:
                log("[snyk] scoop uninstall snyk")
                r = _run([scoop_cmd, "uninstall", "snyk"], timeout=300)
                if r.stdout: log(r.stdout.strip()[-500:])
                if r.stderr: log(r.stderr.strip()[-500:])
            except Exception as e:
                log(f"[snyk] scoop uninstall skipped: {e!r}")
        shim = _scoop_root() / "shims" / "snyk.exe"
        try:
            if shim.exists():
                shim.unlink()
                log(f"[snyk] removed scoop shim: {shim}")
        except Exception as e:
            log(f"[snyk] could not remove scoop shim {shim}: {e!r}")

def _wipe_snyk_configstore(log: Callable[[str], None]) -> None:
    """Delete Snyk's ENTIRE local config file (not just the credential keys that
    clear_snyk_credentials() removes) — org overrides, endpoint overrides, feature
    flags, whatever else may be stale — and reset every in-process cache this module
    keeps about it, so nothing here can paper over a truly fresh state."""
    path = _snyk_configstore_path()
    if path and Path(path).exists():
        try:
            Path(path).unlink()
            log(f"[snyk] removed Snyk config file: {path}")
        except Exception as e:
            log(f"[snyk] could not remove config file {path}: {e!r}")
    else:
        log("[snyk] no local Snyk config file found (nothing to remove)")
    global _CFG_FILE_SEARCHED, _CFG_FILE_PATH, _CFG_CACHE, _CFG_CACHE_MTIME
    _CFG_FILE_SEARCHED, _CFG_FILE_PATH = False, ""
    _CFG_CACHE, _CFG_CACHE_MTIME = {}, 0.0

def reinstall_snyk_clean(log: Callable[[str], None]) -> bool:
    """Full clean reinstall of the Snyk CLI: uninstalls any existing copy (npm/
    standalone/brew/winget), wipes its local config+credential store entirely, resets
    this module's in-process caches, then installs the latest version fresh. The user
    will need to sign in again before the next scan.

    Use this — NOT install_snyk()/ensure_snyk_ready() — when scans fail with a
    Snyk-side error even though `snyk --version` runs fine: those two only repair
    connectivity/PATH problems and deliberately skip a CLI that's already "working",
    so they cannot fix a case where the binary runs but Snyk's backend no longer
    accepts what it sends (e.g. the backend expects a newer CLI release than what's
    installed/cached locally).

    Never touches Reports/ or the app's inventory (apps) — both live entirely under
    this app's own reports_root, never inside Snyk CLI's own OS-level config
    directory, so a scan history and app profiles survive this untouched."""
    log("[snyk] === reinstalación limpia solicitada — esto cerrará la sesión de Snyk ===")
    _uninstall_snyk_binary(log)
    _wipe_snyk_configstore(log)
    global _SNYK_WORKS_CACHE, _SNYK_WORKS_CACHE_AT
    _SNYK_WORKS_CACHE, _SNYK_WORKS_CACHE_AT = None, 0.0
    ok = install_snyk(log, force=True)
    if ok:
        _, detail = _snyk_works(timeout=30)
        log(f"[snyk] reinstalación limpia completa — binario activo: {_which('snyk')} "
            f"({detail}) — inicie sesión de nuevo antes de escanear.")
        # Root cause of "reinstala cada vez que abro": whatever call led here
        # (bootstrap outdated-check, the manual button, or the scan-time
        # auto-reinstall trigger) had just written {"is_current": false, ...}
        # into the on-disk 7-day cache (_VERSION_CHECK_CACHE) BEFORE this
        # function ran -- that write is how check_snyk_version_current() decided
        # a reinstall was needed in the first place. This function used to never
        # touch that cache again, so the stale "outdated" verdict stayed cached
        # for up to 7 days: every following launch's check_snyk_version_current()
        # call (both in _try_fast_boot and in the main boot path) kept reading
        # that same stale entry and forcing another clean reinstall, forever,
        # regardless of the fact that the CLI was already current. Force a fresh
        # check now so the cache reflects reality (should now be is_current=True)
        # before the next launch ever reads it.
        try:
            _is_current, _cache_detail = check_snyk_version_current(log, force=True)
            log(f"[snyk] version cache refreshed post-reinstall: {_cache_detail}")
        except Exception as e:
            log(f"[snyk] could not refresh version cache post-reinstall: {e!r} "
                "— next launch may re-check against a stale cached verdict")
    else:
        log("[snyk] la reinstalación limpia no terminó con una CLI funcional — "
            "revise el log anterior (puede requerir instalación manual).")
    return ok

def start_snyk_auth(log: Callable[[str], None]) -> subprocess.Popen:
    setup_proxy_tls_env(log)
    log("[auth] launching `snyk auth` — browser will open shortly.")
    kwargs: dict = {}
    if IS_WIN:

        kwargs["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP |
                                    subprocess.CREATE_NO_WINDOW)

    env = dict(os.environ)
    env.setdefault("SNYK_DISABLE_ANALYTICS", "1")
    env.setdefault("DISABLE_ANALYTICS", "1")
    return subprocess.Popen([_snyk_bin(), "auth"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace",
                            env=env,
                            **kwargs)

def _parse_json_loose(stdout: str) -> Any:
    if not stdout or not stdout.strip():
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        docs = []
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                try: docs.append(json.loads(line))
                except json.JSONDecodeError: pass
        return docs or None

def _count_vulns(data: Any) -> int:
    projects = (data if isinstance(data, list) else [data]) if data else []
    return sum(
        len((p or {}).get("vulnerabilities") or [])
        for p in projects if isinstance(p, dict))

def _looks_like_result(it: Any) -> bool:
    """True if a parsed item is a genuine scan RESULT (not an error envelope)."""
    if not isinstance(it, dict):
        return False
    return (it.get("ok") is True
            or "vulnerabilities" in it
            or "dependencyCount" in it
            or "packageManager" in it
            or "uniqueCount" in it
            or "runs" in it)

def _error_envelope_msg(data: Any) -> str:
    """Return the error message if `data` is ONLY a Snyk error envelope ({"ok": false, "error": "..."}) with no real…"""
    items = data if isinstance(data, list) else [data]
    if any(_looks_like_result(it) for it in items):
        return ""
    for it in items:
        if isinstance(it, dict) and it.get("ok") is False and it.get("error"):
            err = str(it.get("error"))
            if not _looks_like_auth_error(err):
                return err
    return ""

def _prepare_pip_sandbox(target: Path,
                         log: Callable[[str], None]) -> Optional[dict]:
    req = target / "requirements.txt"
    if not req.exists():
        return None
    venv_dir   = target / ".snyk-venv"
    wheels_dir = target / ".snyk-wheels"
    wheels_dir.mkdir(exist_ok=True)
    scripts = venv_dir / ("Scripts" if os.name == "nt" else "bin")
    py_exe  = scripts  / ("python.exe" if os.name == "nt" else "python")
    if not py_exe.exists():
        log(f"[sandbox] creating isolated venv at {venv_dir}…")
        r = _run([sys.executable, "-m", "venv", str(venv_dir)], timeout=300)
        if r.returncode != 0:
            log(f"[sandbox] venv failed: {(r.stderr or r.stdout).strip()}")
            return None
        _run([str(py_exe), "-m", "pip", "install", "--upgrade", "pip",
              "--disable-pip-version-check"], timeout=600)
    log("[sandbox] downloading wheels (wheels-only, no code executes)…")
    dl = _run([str(py_exe), "-m", "pip", "download", "--only-binary=:all:",
               "--dest", str(wheels_dir), "-r", str(req),
               "--disable-pip-version-check"], timeout=900)
    if dl.stdout: log(dl.stdout.strip()[-1500:])
    if dl.stderr: log(dl.stderr.strip()[-1500:])
    if not list(wheels_dir.glob("*.whl")):
        log("[sandbox] no wheels downloaded; skipping sandbox."); return None
    inst = _run([str(py_exe), "-m", "pip", "install", "--no-index",
                 "--find-links", str(wheels_dir), "--only-binary=:all:",
                 "--no-build-isolation", "-r", str(req),
                 "--disable-pip-version-check"], timeout=900)
    if inst.stdout: log(inst.stdout.strip()[-1500:])
    if inst.stderr: log(inst.stderr.strip()[-1500:])
    installed = (_run([str(py_exe), "-m", "pip", "list", "--format=freeze"],
                      timeout=60).stdout or "").strip()
    if not installed:
        log("[sandbox] venv empty; SCA may report 0."); return None
    log(f"[sandbox] ready ({len(installed.splitlines())} packages visible to Snyk).")
    env = os.environ.copy()
    env["VIRTUAL_ENV"] = str(venv_dir)
    env["PATH"] = str(scripts) + os.pathsep + env.get("PATH", "")
    env.pop("PYTHONHOME", None)
    return env

class SnykScanError(RuntimeError):
    """Raised when a Snyk scan could not complete (e.g. the CLI binary could not be downloaded behind a TLS-inspectin…"""
    def __init__(self, *args, is_auth: bool = False):
        super().__init__(*args)
        self.is_auth = is_auth

def _snyk_json_scan(args, *, target, out_dir, out_name, log, env=None,
                    timeout=1800, write_raw=False,
                    count_label="") -> tuple[Any, Path]:
    log(f"[scan] $ snyk {' '.join(args[1:])}  (cwd={target})")
    base_env = env if env is not None else os.environ.copy()
    r = _run(args, cwd=target, env=base_env, timeout=timeout)
    combined = (r.stdout or "") + (r.stderr or "")
    data = _parse_json_loose(r.stdout or "")

    if data is None and _looks_like_tls_error(combined):
        ca = _find_ca_bundle() or _export_windows_ca_bundle(log)
        if ca:
            log(f"[scan][tls-retry] retrying with NODE_EXTRA_CA_CERTS={ca}")
            env2 = dict(base_env); env2["NODE_EXTRA_CA_CERTS"] = ca
            r = _run(args, cwd=target, env=env2, timeout=timeout)
            data = _parse_json_loose(r.stdout or "")
            combined = (r.stdout or "") + (r.stderr or "")
        if data is None and _looks_like_tls_error(combined):
            log("[scan][tls-retry] CA bundle unavailable/insufficient — "
                "retrying with TLS verification DISABLED "
                "(NODE_TLS_REJECT_UNAUTHORIZED=0) + snyk --insecure.")
            env3 = dict(base_env); env3["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
            args_insecure = list(args)

            if "--insecure" not in args_insecure:
                args_insecure.append("--insecure")
            r = _run(args_insecure, cwd=target, env=env3, timeout=timeout)
            data = _parse_json_loose(r.stdout or "")
            combined = (r.stdout or "") + (r.stderr or "")

    if r.stderr:
        log(r.stderr.strip()[-2000:])

    if data is None and r.stderr:
        data = _parse_json_loose(r.stderr)

    out_path = out_dir / out_name
    out_path.write_text(
        r.stdout or "" if write_raw else json.dumps(data, indent=2),
        encoding="utf-8")

    def _is_auth_fail(d: Any) -> bool:
        items = d if isinstance(d, list) else [d]
        for it in items:
            if isinstance(it, dict) and it.get("ok") is False\
                    and _looks_like_auth_error(str(it.get("error", ""))):
                return True
        return False

    if _is_auth_fail(data) or (data is None and _looks_like_auth_error(combined)):
        raise SnykScanError(
            f"{count_label or 'Snyk'} scan failed: not authenticated to Snyk. "
            f"The saved credential is missing or expired. Click 'Re-login to "
            f"Snyk' to sign in again (this clears any stale token and signs in "
            f"through your organization's SSO).", is_auth=True)

    _env_err = _error_envelope_msg(data)
    if _env_err:
        try:
            _diag = json.dumps(data, indent=2, ensure_ascii=False)[:2000]
        except Exception:
            _diag = repr(data)[:2000]
        log(f"[scan][diag] raw Snyk error envelope for this failure "
            f"(full detail — helps tell a version/org/proxy problem apart from a "
            f"code problem): {_diag}")
        try:
            _vd = _run([_snyk_bin(), "--version"], timeout=15)
            log(f"[scan][diag] snyk binary: {_which('snyk')}  version: "
                f"{(_vd.stdout or _vd.stderr or '?').strip()}")
        except Exception as _e:
            log(f"[scan][diag] could not read snyk --version: {_e!r}")
        raise SnykScanError(
            f"{count_label or 'Snyk'} scan could not analyse the target "
            f"(nothing scannable here): {_env_err}")

    if data is None:
        snippet = (combined.strip() or "no output").splitlines()
        tail = " ".join(snippet[-6:])[:600] if snippet else "no output"
        if _looks_like_tls_error(combined):
            raise SnykScanError(
                f"{count_label or 'Snyk'} scan failed: the Snyk CLI could not "
                f"reach Snyk through the network (TLS/self-signed-certificate "
                f"error from a corporate proxy). Set NODE_EXTRA_CA_CERTS to your "
                f"company CA bundle, or run with --insecure. Details: {tail}")
        raise SnykScanError(
            f"{count_label or 'Snyk'} scan failed — no JSON returned. "
            f"Details: {tail}")

    if count_label:
        log(f"[scan] {count_label} total vulnerabilities: {_count_vulns(data)}")
    log(f"[scan] raw JSON → {out_path}")
    return data, out_path

_DEFAULT_SNYK_ORG = "7c545e26-1865-4ce9-a2e5-2b8c1c215e62"
_SNYK_ORG: str = (os.environ.get("SNYK_ORG", "").strip() or _DEFAULT_SNYK_ORG)

def get_snyk_org() -> str:
    return _SNYK_ORG

def _org_args() -> list[str]:
    """`--org=<id>` flag list, or empty when no org is configured."""
    org = get_snyk_org()
    return [f"--org={org}"] if org else []

def run_snyk_test(target: Path, out_dir: Path,
                  log: Callable[[str], None]) -> tuple[Any, Path]:
    """SCA scan via `snyk test --all-projects`."""
    setup_proxy_tls_env(log)
    sb_env = _prepare_pip_sandbox(target, log)
    args = [_snyk_bin(), "test", "--all-projects", "--detection-depth=10",
            "--strict-out-of-sync=false", "--skip-unresolved",
            *_org_args(), "--json"]
    return _snyk_json_scan(args, target=target, out_dir=out_dir,
                           out_name="snyk_test.json", log=log, env=sb_env,
                           count_label="SCA")

def run_snyk_code(target: Path, out_dir: Path,
                  log: Callable[[str], None]) -> tuple[Any, Path]:
    """SAST scan via `snyk code test`."""
    setup_proxy_tls_env(log)
    return _snyk_json_scan([_snyk_bin(), "code", "test", *_org_args(), "--json"],
                           target=target, out_dir=out_dir,
                           out_name="snyk_code.json",
                           log=log, write_raw=True)

_SARIF_LEVEL = {"critical": "error", "high": "error",
                "medium": "warning", "low": "note", "info": "note"}

def _sarif_run(tool_name: str, results: list[dict]) -> dict:
    rules: dict[str, dict] = {}
    out_results = []
    for r in results:
        rule_id  = r.get("rule_id") or r.get("title") or "finding"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id[:120],
            "shortDescription": {"text": (r.get("title") or rule_id)[:200]},
            "properties": {k: v for k, v in (("cwe", r.get("cwe")),) if v},
        })
        sev = (r.get("severity") or "low").lower()
        msg = r.get("title") or rule_id
        ev  = r.get("evidence") or ""
        loc_uri = r.get("url") or r.get("location") or ""
        res = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(sev, "note"),
            "message": {"text": f"{msg}\n{ev}".strip()},
            "properties": {"severity": sev,
                           "category": r.get("category", "")},
        }
        if loc_uri:
            res["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": loc_uri}}}]
        out_results.append(res)
    return {
        "tool": {"driver": {
            "name": tool_name,
            "informationUri": "https://snyk.io",
            "rules": list(rules.values())}},
        "results": out_results,
    }

def _collect_sca_findings(data) -> list[dict]:
    projects = (data if isinstance(data, list) else [data]) if data else []
    out = []
    for p in projects:
        if not isinstance(p, dict): continue
        for v in (p.get("vulnerabilities") or []):
            if not isinstance(v, dict): continue
            pkg = v.get("packageName") or v.get("package") or ""
            ver = v.get("version") or ""
            out.append({
                "rule_id":  v.get("id") or v.get("title") or "snyk-sca",
                "title":    v.get("title") or v.get("id") or "Vulnerability",
                "severity": (v.get("severity") or "low").lower(),
                "evidence": f"{pkg}@{ver}  " + (
                    " > ".join(map(str, (v.get("from") or [])[:6]))),
                "location": (p.get("displayTargetFile") or p.get("targetFile")
                             or p.get("path") or pkg),
                "cwe": ",".join(
                    v.get("identifiers", {}).get("CWE", []) or []),
                "category": "sca",
            })
    return out

def _read_json(path: Path):
    """Load a JSON file, returning None if missing or unparseable."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def export_sarif(out_dir: Path) -> Optional[Path]:
    """Build a single SARIF 2.1.0 log from every scanner's raw output in out_dir."""
    runs: list[dict] = []

    def _load(name): return _read_json(out_dir / name)

    sca = _load("snyk_test.json")
    if sca is not None:
        sca_findings = _collect_sca_findings(sca)
        if sca_findings:
            runs.append(_sarif_run("Snyk Open Source (SCA)", sca_findings))

    code = _load("snyk_code.json")
    if isinstance(code, dict) and isinstance(code.get("runs"), list):
        runs.extend(code["runs"])
    elif isinstance(code, list):
        for doc in code:
            if isinstance(doc, dict) and isinstance(doc.get("runs"), list):
                runs.extend(doc["runs"])

    for name, tool in (("dast.json", "DAST Crawler"),
                       ("api.json",  "API Scanner")):
        d = _load(name)
        if isinstance(d, dict) and d.get("findings"):
            runs.append(_sarif_run(tool, d["findings"]))

    if not runs:
        return None
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }
    path = out_dir / "findings.sarif"
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return path

def export_merged_json(out_dir: Path) -> Optional[Path]:
    """One flat JSON array of all non-SAST findings (DAST + API + SCA)."""
    merged: list[dict] = []

    def _load(name): return _read_json(out_dir / name)

    sca = _load("snyk_test.json")
    if sca is not None:
        merged.extend(_collect_sca_findings(sca))
    for name in ("dast.json", "api.json"):
        d = _load(name)
        if isinstance(d, dict):
            merged.extend(d.get("findings") or [])
    if not merged:
        return None
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    merged.sort(
        key=lambda x: order.get((x.get("severity") or "low").lower(), 5))
    path = out_dir / "findings_merged.json"
    path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    return path

from secrets_scanner import (
    SEVERITY_ORDER, GIT_SECRETS_RAW_URL,
    get_git_secrets_status, get_engine_label, ensure_git_secrets,
    scan_path, redact, redact_line, render_secrets_html, write_secrets_report,
    load_baseline, save_baseline_entry, remove_baseline_entry,
)
import secrets_scanner as secrets_scanner_module

class _PathListDisplay:
    """Drop-in replacement for the tk.Listbox that used to show the Estático tab's queued folders/files: renders each…"""

    def __init__(self, parent, *, font, fg, bg, select_bg, select_fg):
        self.frame = tk.Frame(parent, bg=bg)
        self._font = font
        self._fg = fg
        self._bg = bg
        self._select_bg = select_bg
        self._select_fg = select_fg
        self._items: list[str] = []
        self._selected: set[int] = set()
        self._anchor: Optional[int] = None
        self._empty_lbl: Optional["tk.Label"] = None
        self._redraw()

    def pack(self, **kw): self.frame.pack(**kw)
    def grid(self, **kw): self.frame.grid(**kw)

    def _redraw(self) -> None:
        for w in self.frame.winfo_children():
            w.destroy()
        if not self._items:
            self._empty_lbl = tk.Label(
                self.frame, text="  (ninguna ruta agregada)", font=self._font,
                bg=self._bg, fg=T["muted"], anchor="w")
            self._empty_lbl.pack(fill="x")
            return
        self._empty_lbl = None
        for i, path in enumerate(self._items):
            sel = i in self._selected
            row = tk.Label(
                self.frame, text=f"  {path}", font=self._font, anchor="w",
                bg=self._select_bg if sel else self._bg,
                fg=self._select_fg if sel else self._fg,
                cursor="hand2")
            row.pack(fill="x")
            row.bind("<Button-1>", lambda e, i=i: self._on_click(i, e))

    def _on_click(self, idx: int, event) -> None:
        ctrl = bool(event.state & 0x0004)
        shift = bool(event.state & 0x0001)
        if shift and self._anchor is not None:
            lo, hi = sorted((self._anchor, idx))
            self._selected = set(range(lo, hi + 1))
        elif ctrl:
            if idx in self._selected: self._selected.discard(idx)
            else: self._selected.add(idx)
            self._anchor = idx
        else:
            self._selected = {idx}
            self._anchor = idx
        self._redraw()

    def get(self, first, last=None):
        lo = 0 if first in (0, "0") else int(first)
        if last is None:
            return self._items[lo] if 0 <= lo < len(self._items) else ""
        hi = (len(self._items) - 1) if last == "end" else int(last)
        return tuple(self._items[lo:hi + 1])

    def insert(self, index, value) -> None:
        if index == "end":
            self._items.append(value)
        else:
            self._items.insert(int(index), value)
        self._redraw()

    def delete(self, first, last=None) -> None:
        if not self._items:
            return
        lo = 0 if first in (0, "0") else int(first)
        if last is None:
            hi = lo
        elif last == "end":
            hi = len(self._items) - 1
        else:
            hi = int(last)
        del self._items[lo:hi + 1]
        self._selected = set()
        self._anchor = None
        self._redraw()

    def curselection(self):
        return tuple(sorted(self._selected))

    def size(self) -> int:
        return len(self._items)

class _StaticTabMixin(secrets_scanner_module._SecretsPanelMixin):
    def _sev_brand_color(self, sev):
        sev = _sev_norm(sev)
        if sev in ("critical", "high"): return T["err"]
        if sev == "medium":             return T["accent"]
        return T["muted"]

    def _sev_leaf_tag(self, sev):
        sev = _sev_norm(sev)
        if sev in ("critical", "high"): return "crit"
        if sev == "medium":             return "med"
        return "muted"

    def _apply_group_tags(self, tree):
        tree.tag_configure("group", foreground=T["text"], font=(_FUI, 12))
        tree.tag_configure("crit",  foreground=T["err"])
        tree.tag_configure("med",   foreground=T["text"])
        tree.tag_configure("muted", foreground=T["muted"])

    def _group_tree(self, parent, tree_col, cols, headings, height):
        """Árbol colapsable de 2 niveles (grupo → hallazgos) con estilo de marca."""

        outer = tk.Frame(parent, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["accent"])
        outer.pack(fill="both", expand=True)
        tk.Frame(outer, bg=T["border_bg"], height=2).pack(fill="x", side="top")
        tf = tk.Frame(outer, bg=T["panel_bg"]); tf.pack(fill="both", expand=True)
        tree = ttk.Treeview(tf, columns=cols, show="tree headings", height=height)
        tcol_txt, tcol_w = tree_col
        tree.heading("#0", text=tcol_txt, anchor="w",
                    command=lambda: _group_tree_sort_col(tree, "#0", False))
        tree.column("#0", width=tcol_w, stretch=True, anchor="w")
        for c, (txt, w, anchor, stretch) in zip(cols, headings):
            tree.heading(c, text=txt, anchor=anchor,
                        command=lambda col=c: _group_tree_sort_col(tree, col, False))
            tree.column(c, width=w, anchor=anchor, stretch=stretch)
        tree.pack(side="left", fill="both", expand=True)
        ttk.Scrollbar(tf, command=tree.yview, orient="vertical").pack(side="right", fill="y")
        self._apply_group_tags(tree)
        return tree

    def _tree_empty(self, tree, msg="Sin hallazgos — ejecute un escaneo."):
        for iid in tree.get_children(): tree.delete(iid)
        tree.insert("", "end", text="  " + msg, tags=("muted",))

    def _set_panel_summary(self, lbl, total, worst):
        if lbl is None: return
        if total == 0:
            lbl.config(text="sin hallazgos")
        else:
            lbl.config(text=f"{total} finding{'' if total == 1 else 's'}")

    def _render_sca(self, projects):
        """SCA is about *which dependency to upgrade* — group by package, surface the fix version, collapse the individua…"""
        tree = self._static_sca_tree
        for iid in tree.get_children(): tree.delete(iid)
        groups: dict = {}
        for proj in projects or []:
            for i in proj.get("issues", []):
                groups.setdefault(i.get("package", "—"), []).append(i)
        total = 0; worst = "info"
        for pkg in sorted(groups):
            issues = groups[pkg]; total += len(issues)
            gw = "info"; fix = ""
            for i in issues:
                s = _sev_norm(i.get("severity"))
                if _SEV_RANK[s] > _SEV_RANK[gw]: gw = s
                if not fix and i.get("fixedIn") not in (None, "", "—"): fix = str(i.get("fixedIn"))
            if _SEV_RANK[gw] > _SEV_RANK[worst]: worst = gw
            p = tree.insert("", "end", text=f"{pkg}   ({len(issues)})",
                            values=(gw.upper(), ("→ " + fix) if fix else "—"), tags=("group",), open=False)
            for i in issues:
                s = _sev_norm(i.get("severity"))
                fx = i.get("fixedIn"); fx = ("→ " + str(fx)) if fx not in (None, "", "—") else "—"
                tree.insert(p, "end", text="   " + (i.get("title", "") or ""),
                            values=(s.upper(), fx), tags=(self._sev_leaf_tag(s),))
        if total == 0: self._tree_empty(tree)
        self._set_panel_summary(self._sca_summary, total, worst)

    def _render_sast(self, files):
        """SAST is about *where in the code* — group by file (data already is), collapse the per-line findings underneath…"""
        tree = self._static_sast_tree
        for iid in tree.get_children(): tree.delete(iid)
        total = 0; worst = "info"
        for fobj in files or []:
            issues = fobj.get("issues", [])
            if not issues: continue
            total += len(issues); gw = "info"
            for i in issues:
                s = _sev_norm(i.get("severity"))
                if _SEV_RANK[s] > _SEV_RANK[gw]: gw = s
            if _SEV_RANK[gw] > _SEV_RANK[worst]: worst = gw
            p = tree.insert("", "end", text=f"{fobj.get('file', '—')}   ({len(issues)})",
                            values=(gw.upper(), ""), tags=("group",), open=False)
            for i in issues:
                s = _sev_norm(i.get("severity"))
                tree.insert(p, "end", text="   " + (i.get("title", "") or ""),
                            values=(s.upper(), str(i.get("line", "?"))), tags=(self._sev_leaf_tag(s),))
        if total == 0: self._tree_empty(tree)
        self._set_panel_summary(self._sast_summary, total, worst)

    def _build_tab_static(self, parent):
        pad = self._scrollable(parent)

        self._static_route_btn_row = tk.Frame(pad, bg=T["bg"])
        self._static_route_btn_row.pack(fill="x", pady=(0, 4), anchor="w")

        top_row = tk.Frame(pad, bg=T["bg"]); top_row.pack(fill="x", pady=(0, 2))

        fold = self._side_card(top_row, "Ruta")

        self._static_paths_lb = _PathListDisplay(
            fold, font=(_FMONO, 12), fg=T["card_fg"], bg=T["panel_bg"],
            select_bg=T["surface2"], select_fg=T["card_fg"])
        self._static_paths_lb.pack(fill="x")

        def _add_folder():
            initial = self._target_var.get() or str(SCRIPT_DIR)
            d = filedialog.askdirectory(title="Agregar carpeta al escaneo", initialdir=initial)
            if d:
                existing = list(self._static_paths_lb.get(0, "end"))
                if d not in existing:
                    self._static_paths_lb.insert("end", d)
                self._target_var.set(d)
                self._persist_static_paths()

        def _add_files():
            initial = self._target_var.get() or str(SCRIPT_DIR)
            files = filedialog.askopenfilenames(
                title="Agregar archivos o .csproj al escaneo",
                initialdir=initial,
                filetypes=[
                    ("Todos los compatibles", "*.csproj *.sln *.json *.py *.js *.ts *.cs *.java *.go *.rb *.php"),
                    ("Proyectos Visual Studio", "*.csproj *.sln"),
                    ("Manifiestos de dependencias", "*.json *.xml *.lock *.toml *.gradle"),
                    ("Código fuente", "*.py *.js *.ts *.cs *.java *.go *.rb *.php *.cpp *.c *.h"),
                    ("Todos los archivos", "*.*"),
                ])
            if files:
                existing = list(self._static_paths_lb.get(0, "end"))
                for f in files:

                    p = Path(f)
                    if p.suffix.lower() == ".csproj":
                        folder = str(p.parent)
                        if folder not in existing:
                            self._static_paths_lb.insert("end", folder)
                            existing.append(folder)
                            self._log_line(f"[static] .csproj detected: using folder '{folder}'")
                    else:
                        if f not in existing:
                            self._static_paths_lb.insert("end", f)
                            existing.append(f)
                if files:
                    self._target_var.set(str(Path(files[-1]).parent))
                self._persist_static_paths()

        def _remove_selected():
            sel = list(self._static_paths_lb.curselection())
            if not sel:
                return

            def _do_remove():
                for idx in reversed(sel):
                    self._static_paths_lb.delete(idx)
                items = self._static_paths_lb.get(0, "end")
                if items: self._target_var.set(items[-1])
                else: self._target_var.set("")
                self._persist_static_paths()

            def _remove_and_clear():
                self._clear_static_results()
                _do_remove()

            # Only ask when there's actually something on screen that could get
            # confused with whatever gets scanned next (see _clear_static_results) —
            # no point interrupting the common case of just tidying the path list
            # before a first scan.
            if getattr(self, "_static_results_visible", False):
                popup = self._create_popup("Quitar ruta")
                self._popup_hdr(popup, "Quitar ruta", icon="⚠")
                self._centered_msg(
                    popup, "⚠", T["accent"], "Quitar ruta",
                    "Esta ruta tiene resultados de un escaneo anterior en pantalla.\n\n"
                    "Si los deja y luego escanea otra carpeta, el reporte combinará "
                    "ambos resultados (SCA/SAST/Secretos se muestran acumulados por "
                    "diseño, no solo del último escaneo).\n\n"
                    "¿Desea limpiar esos resultados antes de continuar?",
                    T["text"])
                def _yes():
                    popup.close(); _remove_and_clear()
                def _no():
                    popup.close(); _do_remove()
                self._popup_foot(
                    popup,
                    ("  Cancelar  ", popup.close, "flat"),
                    ("  Solo quitar la ruta  ", _no, "outline"),
                    ("  Limpiar resultados anteriores y quitar  ", _yes, "accent"),
                )
            else:
                _do_remove()

        self._btn(self._static_route_btn_row, "+ Carpeta", lambda: _add_folder(), "accent").pack(side="left", padx=(0, 2))
        self._btn(self._static_route_btn_row, "+ Archivo", lambda: _add_files(), "accent").pack(side="left", padx=(0, 2))
        _rm_btn = self._icon_square_btn(self._static_route_btn_row, "🗑", lambda: _remove_selected(), danger=True)
        _rm_btn.pack(side="left", padx=(0, 2))
        run_btn = self._icon_square_btn(self._static_route_btn_row, "▶",
                                        lambda: self._start_static_scan({"sca", "code", "secrets"}))
        run_btn.pack(side="left")
        self._static_run_btns = [run_btn]

        _saved_paths = getattr(self, "_saved_static_paths", None)
        if _saved_paths:
            for p in _saved_paths:
                self._static_paths_lb.insert("end", p)

            self._target_var.set(_saved_paths[-1])
        elif self._target_var.get():
            self._static_paths_lb.insert("end", self._target_var.get())

        results_row = tk.Frame(pad, bg=T["bg"])
        sca_half = tk.Frame(results_row, bg=T["bg"]); sca_half.pack(side="left", fill="both", expand=True, padx=(0, _CARD_GAP // 2))
        sast_half = tk.Frame(results_row, bg=T["bg"]); sast_half.pack(side="left", fill="both", expand=True, padx=(_CARD_GAP // 2, 0))
        self._static_results_row = results_row

        sca_inner, sca_right = self._panel(sca_half, "SCA", pady=(0, 0))
        self._sca_summary = tk.Label(sca_right, text="sin hallazgos", font=(_FUI, 12),
                                     bg=T["pill_idle_bg"], fg=T["pill_idle_fg"]); self._sca_summary.pack(side="right")
        self._static_sca_tree = self._group_tree(
            sca_inner, ("Paquete  /  Vulnerabilidad", 220), ("sev", "fix"),
            [("Severidad", 90, "w", False), ("Corrección disponible", 140, "w", False)], height=7)
        self._tree_empty(self._static_sca_tree)

        sast_inner, sast_right = self._panel(sast_half, "SAST", pady=(0, 0))
        self._sast_summary = tk.Label(sast_right, text="sin hallazgos", font=(_FUI, 12),
                                      bg=T["pill_idle_bg"], fg=T["pill_idle_fg"]); self._sast_summary.pack(side="right")
        self._static_sast_tree = self._group_tree(
            sast_inner, ("Archivo  /  Hallazgo", 220), ("sev", "line"),
            [("Severidad", 90, "w", False), ("Línea", 70, "center", False)], height=7)
        self._tree_empty(self._static_sast_tree)

        self._static_secrets_wrap = self._build_secrets_panel(pad)

        self._static_results_visible = False

    def _reveal_static_results(self) -> None:
        """Show the SCA/SAST/Secrets cards — called once a static scan has actually completed (even with zero findings in…"""
        if getattr(self, "_static_results_visible", False):
            return
        row = getattr(self, "_static_results_row", None)
        wrap = getattr(self, "_static_secrets_wrap", None)
        if row is not None:
            row.pack(fill="x", pady=(0, _CARD_GAP))
        if wrap is not None:
            wrap.pack(fill="x")
        self._static_results_visible = True

    def _clear_static_results(self) -> None:
        """Wipe both the visible SCA/SAST/Secrets panels AND the persisted per-kind
        state (ScanStateStore) those panels — and the next scan's cumulative report
        — are built from. Doing only the visible half would leave the confusing
        part of the bug in place: build_cumulative_context() would still quietly
        pull the removed route's last-known sca/code/secrets result into the NEXT
        target's report even though the screen looked clean."""
        if hasattr(self, "_static_sca_tree"):
            self._render_sca([])
        if hasattr(self, "_static_sast_tree"):
            self._render_sast([])
        if hasattr(self, "_secrets_box"):
            self._render_secrets([], target=None, baseline_suppressed=[])
        if hasattr(self, "_static_count_lbl"):
            self._static_count_lbl.config(text="Sin resultados — ejecute un escaneo.")
        if hasattr(self, "_static_open_btn"):
            self._static_open_btn.config(state="disabled")
        self._last_static_report = None
        self._last_context = None
        try:
            state = getattr(self, "_scan_state", None)
            if state is not None:
                state.clear_kinds(("sca", "code", "secrets"))
        except Exception as e:
            self._emit_log(f"[static] no se pudo limpiar el estado persistido: {e!r}")
        self._emit_log("[static] resultados del escaneo anterior eliminados.")

    def _start_static_scan(self, sel: set):
        """Public entry point — the Static-analysis tab's '▶ Análisis estático' button."""
        if self._static_busy:
            self._log_line("[static] a scan is already running"); return
        self._confirm_scan_without_app(lambda: self._run_static_scan_now(sel))

    def _run_static_scan_now(self, sel: set):

        changed = False
        for k in ("sca", "code", "secrets"):
            if k in sel:
                var = self._scan_vars.get(k)
                if var is not None and not var.get():
                    var.set(1); changed = True
                apply_fn = getattr(self, "_stage_apply", {}).get(k)
                if apply_fn:
                    try: apply_fn(True)
                    except Exception: pass
        if changed:
            self._refresh_scan_btn(); self._persist_scan_stages()

        raw_paths = list(getattr(self, "_static_paths_lb", None) and
                         self._static_paths_lb.get(0, "end") or [])

        paths = [p for p in raw_paths if p.strip() and not p.strip().startswith("(empty")]
        if not paths:

            tv = self._target_var.get().strip()
            if tv: paths = [tv]
        if not paths:
            self._show_warn_popup("Análisis estático",
                "Sin carpetas ni archivos seleccionados.\n\n"
                "Use '📂 + Carpeta' o '📄 + Archivo(s) / .csproj' para agregar objetivos."); return

        valid_paths = []
        for p in paths:
            pp = Path(p).resolve()
            if pp.exists():
                valid_paths.append(pp)
            else:
                self._log_line(f"[static] ⚠ path not found, skipping: {p}")
        if not valid_paths:
            self._show_warn_popup("Análisis estático",
                "Ninguna de las rutas seleccionadas existe en disco.\n\n"
                "Verifique las rutas e intente de nuevo."); return

        self._static_targets = valid_paths
        self._target_var.set(str(valid_paths[0]))

        if {"sca", "code"} & sel:
            checks = self._checks or {}
            auth_ok = bool(checks.get("auth") and checks["auth"].ok)
            if not auth_ok:
                self._show_warn_popup("Análisis estático",
                    "SCA y SAST requieren una sesión SSO activa en Snyk.\n\n"
                    "Vaya a la pestaña ▶ Ejecutar → Prerrequisitos y haga clic en '🔑 Iniciar sesión SSO'.")
                return
        self._static_run_sel = sel
        for b in getattr(self, "_static_run_btns", []):
            b.config(state="disabled")
        if hasattr(self, "_static_count_lbl"):
            self._static_count_lbl.config(text="Escaneando… (" + " + ".join(sorted(sel)).upper() + ")")
        self._run_async(self._static_scan, label="static analysis",
                        busy_attr="_static_busy", done_kind="__static_done__")

    @staticmethod
    def _dir_has_files(p) -> bool:
        """True if the target contains at least one regular file (recursive), or is itself a file."""
        try:
            p = Path(p)
            if p.is_file():
                return True
            for child in p.rglob("*"):
                if child.is_file():
                    return True
        except Exception:
            return True
        return False

    def _static_scan(self):
        """Iterate EVERY queued target (multi-folder)."""
        self._static_cancel_evt.clear()
        sel = getattr(self, "_static_run_sel", {"sca", "code", "secrets"})
        targets = getattr(self, "_static_targets", None)
        if not targets:
            tv = self._target_var.get().strip()
            targets = [tv] if tv else []
        targets = [Path(x).resolve() for x in targets]
        if not targets:
            self._emit_log("[static] sin objetivos — nada que escanear")
            self._event_queue.put(("static_results", None)); return

        self._event_queue.put(("pipeline_reset", None))

        scanned = 0
        total_targets = len(targets)
        batch_summaries: list[dict] = []
        for i, t in enumerate(targets, 1):
            if self._static_cancel_evt.is_set():
                self._emit_log("[static] cancelado — objetivos restantes omitidos")
                break
            if not t.exists():
                self._emit_log(f"[static] ⚠ ruta inexistente, se omite: {t}")
                batch_summaries.append({"path": str(t), "scanned": False, "reason": "ruta inexistente"})
                continue
            if not self._dir_has_files(t):
                self._emit_log(f"[static] ⚠ objetivo vacío (sin archivos), se omite: {t}")
                batch_summaries.append({"path": str(t), "scanned": False, "reason": "carpeta vacía"})
                continue
            self._emit_log(f"[static] === objetivo {i}/{total_targets}: {t} ===")
            summary = self._static_scan_one(t, sel, route_index=i - 1, route_total=total_targets)
            if summary:
                batch_summaries.append(summary)
            scanned += 1

        if scanned == 0:
            self._emit_log("[static] ningún objetivo escaneable "
                           "(todas las carpetas vacías o inexistentes)")
            self._event_queue.put(("static_results", None))
            return

        if total_targets > 1:
            self._build_static_batch_index(batch_summaries)

    def _build_static_batch_index(self, batch_summaries: list[dict]) -> None:
        """More than one folder was queued for this run — build the linking/ aggregating index page and make IT (not any…"""
        try:
            from report_engine import render_static_batch_index
            reports_root = Path(self._reports_var.get()).resolve()
            _report_label, app_reports_root = self._scoped_report_paths(reports_root)
            idx_path = render_static_batch_index(
                batch_summaries, app_reports_root, filename=f"index_{_ts()}.html")
            self._emit_log(f"[report] índice de análisis por carpetas ({len(batch_summaries)}) → {idx_path}")
            self._last_report = idx_path
            self._last_static_report = idx_path
            self._event_queue.put(("report", {"path": str(idx_path), "primary": True}))
        except Exception as e:
            self._emit_log(f"[report] no se pudo construir el índice del lote: {e!r}")

    def _static_scan_one(self, target, sel, route_index: int = 0, route_total: int = 1):
        """Run the selected folder-based analyses (SCA / SAST / Secrets) for a SINGLE target through the unified report p…"""
        target = Path(target).resolve()
        reports_root = Path(self._reports_var.get()).resolve(); reports_root.mkdir(parents=True, exist_ok=True)
        active_app = getattr(self, "_active_app", None)
        _report_label, app_reports_root = self._scoped_report_paths(reports_root)
        mode = "+".join(sorted(sel))
        out_dir = app_reports_root / f"report_{_ts()}_{mode}"; out_dir.mkdir(parents=True, exist_ok=True)
        self._session_begin("static", set(sel))
        import audit_log
        audit_log.write_event(reports_root, "scan_start", actor=self._user,
                              app=(active_app.get("name") if active_app else ""),
                              mode=mode, target=str(target), out_dir=str(out_dir), lane="static",
                              log=self._emit_log)
        self._emit_log(f"[static] pipeline: {mode.upper()}")
        self._emit_log(f"[static] output → {out_dir}")
        _snyk_usable = True
        if {"sca", "code"} & sel:
            try:
                if not ensure_snyk_ready(self._emit_log):
                    _snyk_usable = False
                    self._emit_log("[static] Snyk CLI is not runnable — "
                                   "skipping SCA/SAST. Click Fix to repair it.")
            except Exception as e:
                self._emit_log(f"[static] snyk readiness check error: {e!r}")
        try: v = _run(["snyk", "--version"]).stdout.strip()
        except Exception: v = "?"

        results: dict[str, Any] = {"sca": None, "code": None, "dast": None, "api": None, "secrets": None}

        failed_stages: set[str] = set()
        failed_reasons: dict[str, str] = {}

        self._event_queue.put(("static_route_start",
                               (route_index, route_total,
                                [k for k in ("sca", "code", "secrets") if k in sel])))
        for k in ("sca", "code", "secrets"):
            running = k in sel and (_snyk_usable or k == "secrets")
            self._event_queue.put(("stage", (k, "running" if running else "skipped")))

        jobs: list[tuple[str, Callable[[], None]]] = []
        if "sca" in sel and _snyk_usable:
            jobs.append(("sca", lambda: results.__setitem__(
                "sca", run_snyk_test(target, out_dir, self._emit_log)[0])))
            self.after(0, lambda: self._start_stage_pulse("sca"))
        if "code" in sel and _snyk_usable:
            jobs.append(("code", lambda: results.__setitem__(
                "code", run_snyk_code(target, out_dir, self._emit_log)[0])))
            self.after(0, lambda: self._start_stage_pulse("code"))
        if "secrets" in sel:
            def _run_secrets_stage():
                self._emit_log("[secrets] running secret scan…")
                result = scan_path(target, self._emit_log, cancel=self._static_cancel_evt,
                                   git_secrets_status=get_git_secrets_status(),
                                   progress=lambda n, t: self._event_queue.put(
                                       ("card_progress", ("secrets", n, t))))
                sec_dir = out_dir / "secrets"
                write_secrets_report(result, sec_dir)
                self._emit_log(f"[secrets] {result['total']} finding(s) across "
                               f"{result['scanned_files']} file(s)")
                results["secrets"] = result
            jobs.append(("secrets", _run_secrets_stage))

        def run_stage(item):
            key, fn = item
            try:
                fn(); self._event_queue.put(("stage", (key, "done")))
            except Exception as e:
                self._event_queue.put(("stage", (key, "failed")))
                failed_stages.add(key)
                failed_reasons[key] = str(e)
                self._emit_log(f"[static] {key} failed: {e!r}")
                if getattr(e, "is_auth", False):
                    self._event_queue.put(("auth_required", None))

        try:
            if len(jobs) > 1:
                self._emit_log(f"[static] running {len(jobs)} analyses concurrently")
                with ThreadPoolExecutor(max_workers=len(jobs)) as ex_:
                    list(ex_.map(run_stage, jobs))
            else:
                for j in jobs: run_stage(j)

            if failed_stages:

                self._emit_log(
                    "[static] ⚠ " + "/".join(sorted(failed_stages)).upper() +
                    " no se completó — el resultado de este objetivo es "
                    "INCOMPLETO, no interprete el total como un escaneo limpio.")

            # Matches ONLY the genuine SNYK-0003 "Client request cannot be processed"
            # backend-rejection signature (the literal text Snyk's own API returns,
            # `_env_err` in _snyk_json_scan) -- NOT the wrapper phrase "could not
            # analyse the target", which is OUR OWN text and appears on every single
            # Snyk envelope error regardless of cause (no manifest found, org lacks an
            # entitlement, wrong folder, anything). Matching the wrapper phrase was a
            # real bug: it auto-reinstalled Snyk for devs whose actual problem was
            # totally unrelated (e.g. "Could not detect supported target files" /
            # "Snyk Code is not supported for your current organization") and forced
            # them to re-login for nothing.
            _backend_rejected = {k for k in failed_stages
                                 if "the request cannot be processed" in failed_reasons.get(k, "").lower()}
            if _backend_rejected and not getattr(self, "_snow_snyk_auto_reinstall_done", False):
                self._snow_snyk_auto_reinstall_done = True
                self._emit_log(
                    "[snyk] ⚠ Snyk rechazó la solicitud a nivel de servidor para "
                    + "/".join(sorted(_backend_rejected)).upper() +
                    " aunque la CLI local corre sin problemas — normalmente esto "
                    "significa que el backend ya no acepta esta versión/instalación "
                    "de la CLI. Reinstalando automáticamente la versión más "
                    "reciente (misma acción que '🧹 Reinstalar (limpio)')…")
                try:
                    reinstall_snyk_clean(self._emit_log)
                    self._emit_log(
                        "[snyk] reinstalación automática completa — inicie sesión de "
                        "nuevo (icono 🔑, arriba a la derecha) antes de re-escanear "
                        "esta carpeta.")
                except Exception as e:
                    self._emit_log(f"[snyk] la reinstalación automática falló: {e!r}")
            elif _backend_rejected:
                self._emit_log(
                    "[snyk] ⚠ Snyk sigue rechazando la solicitud para "
                    + "/".join(sorted(_backend_rejected)).upper() +
                    " incluso tras la reinstalación automática de esta sesión — "
                    "puede requerir revisión manual (versión de CLI, organización, "
                    "proxy).")

            # "Cannot build Maven dependency tree" -- Snyk shells out to `mvn` itself
            # to build the dependency graph; if THAT fails (missing/old Maven Dependency
            # Plugin, mvn not on PATH, an unreachable internal repo, wrong JDK, etc.),
            # Snyk just reports this generic message with no further detail. This is
            # never a CLI-version problem (confirmed: same failure reproduces running
            # `snyk test` directly in a terminal/IDE, outside this app entirely) --
            # point straight at Snyk's own official diagnostic instead of guessing.
            _maven_tree_issue = {k for k in failed_stages
                                 if "cannot build maven dependency tree" in failed_reasons.get(k, "").lower()}
            if _maven_tree_issue:
                self._emit_log(
                    "[snyk] ℹ️ " + "/".join(sorted(_maven_tree_issue)).upper() +
                    ": Snyk no pudo construir el árbol de dependencias de Maven — "
                    "esto es un problema del proyecto/Maven, NO de la versión de "
                    "Snyk ni de este programa (el mismo error ocurre corriendo "
                    "'snyk test' directo en terminal/IDE, fuera de este escáner). "
                    "Para diagnosticar la causa real, corra esto en esa carpeta: "
                    'mvn dependency:tree -DoutputType=dot --file="pom.xml" — si '
                    "ese comando TAMBIÉN falla, el problema está en Maven/el "
                    "proyecto (mvn no está en el PATH, repositorio interno "
                    "inalcanzable, plugin Maven Dependency <2.2, versión de JDK, "
                    "settings.xml); si el comando SÍ funciona pero Snyk sigue "
                    "fallando, es caso para soporte de Snyk.")

            # Org access/permissions -- literally Snyk's own documented V1 API 404
            # response ("Org {id} was not found or you may not have the correct
            # permissions to access the org"). Confirmed real-world root cause: the
            # affected dev had authenticated via email/password directly on Snyk's
            # login page instead of clicking "Login with SSO" -- that logs into a
            # PERSONAL Snyk instance tied to that email address, not the company's
            # org, so every --org=<company org id> call 404s no matter how correct
            # the CLI/org id are. Re-login through SSO fixed it. Kept the org-
            # membership explanation as a secondary note since the same error
            # signature could in principle also mean the account genuinely isn't a
            # member of this org yet (Group membership alone doesn't grant it) --
            # but SSO re-login is the fix confirmed to actually work in practice.
            _org_access_issue = {k for k in failed_stages
                                 if "permissions to access the org" in failed_reasons.get(k, "").lower()}
            if _org_access_issue:
                _org_m = re.search(r"[Oo]rg (\S+) was not found", " ".join(
                    failed_reasons.get(k, "") for k in _org_access_issue))
                _org_id = _org_m.group(1) if _org_m else _DEFAULT_SNYK_ORG
                self._emit_log(
                    "[snyk] ℹ️ " + "/".join(sorted(_org_access_issue)).upper() +
                    f": esta sesión de Snyk no tiene acceso a la organización "
                    f"{_org_id}. Causa más común: se inició sesión con correo y "
                    f"password directo en vez de SSO — eso entra a una instancia "
                    f"PERSONAL de Snyk (la de ese correo), no a la de la empresa. "
                    f"SOLUCIÓN: dé clic en el ícono de Snyk (esquina superior "
                    f"derecha) → '🔁 Re-iniciar sesión' → en la página que abre el "
                    f"navegador, elija 'Login with SSO' — NO capture correo y "
                    f"password directamente ahí. Si ya inició sesión con SSO y el "
                    f"error persiste, puede que la cuenta no esté agregada a esta "
                    f"organización específica (pertenecer al grupo de Snyk no basta) "
                    f"— en ese caso pida a un admin de Snyk que la agregue en "
                    f"Settings → Members, a nivel Organización.")

            state = self._scan_state
            for kind in ("sca", "code", "secrets"):
                raw = results.get(kind)
                if raw is not None:
                    try:
                        state.save_kind(kind, raw, target=str(target), snyk_version=v, mode=mode)
                        self._emit_log(f"[state] {kind} result persisted")
                    except Exception as e:
                        self._emit_log(f"[state] could not save {kind}: {e!r}")

            ctx = build_cumulative_context(state, target_hint=target,
                                           snyk_version_hint=v, current_results=results)
            ctx["scan_mode"] = mode
            ctx["failed_stages"] = sorted(failed_stages)
            ctx["incomplete"] = bool(failed_stages)

            _batch = getattr(self, "_static_targets", None) or [target]
            ctx["batch_targets"] = [str(Path(t).resolve()) for t in _batch]

            _snow_rec = None
            try:
                from servicenow_tickets import summarize_static, sync_ticket, public_view
                _snow_relevant = {"sca", "code", "secrets"} & sel
                _snow_have_data = any(results.get(k) is not None for k in ("sca", "code", "secrets"))
                if _snow_relevant & failed_stages:
                    self._emit_log("[servicenow] etapa(s) incompleta(s) en este escaneo — "
                                   "se omite sincronización de ticket para este repositorio")
                elif _snow_relevant and _snow_have_data:
                    _snow_summary = summarize_static(results.get("sca"), results.get("code"),
                                                      results.get("secrets"), target, v)
                    _snow_rec = sync_ticket(
                        reports_root, kind="static", name=target.name, summary=_snow_summary,
                        app_name=(active_app.get("name") if active_app else ""),
                        actor=getattr(self, "_user", ""), log=self._emit_log)
            except ImportError as e:
                self._emit_log(
                    f"[servicenow] no se pudo importar servicenow_tickets.py ({e!r}) — "
                    f"ese archivo (y test_servicenow_ticket.py) deben estar en la MISMA "
                    f"carpeta que static_scanner.py para que el escáner pueda crear/"
                    f"actualizar tickets automáticamente. Se omite la sincronización de "
                    f"este ticket.")
            except Exception as e:
                self._emit_log(f"[servicenow] no se pudo sincronizar el ticket: {e!r}")
            ctx["servicenow_tickets"] = [public_view(_snow_rec)] if _snow_rec else []

            self._emit_log("[report] building cumulative report (all scan types merged)")
            _base = _report_basename(self._user, mode)
            report_html = render_html(ctx, out_dir, filename=f"{_base}.html")
            self._emit_log(f"[report] HTML → {report_html}")
            try:
                csv_path = export_csv(ctx, out_dir / f"{_base}.csv", report_label=_report_label)
                self._emit_log(f"[report] CSV bundle (ZIP): {csv_path}")
            except Exception as e:
                self._emit_log(f"[report] CSV export skipped: {e!r}")
            sec_html_src = out_dir / "secrets" / "secrets.html"
            if sec_html_src.exists():
                try:
                    sec_html_dst = out_dir / f"{_base}_secrets.html"
                    shutil.copyfile(sec_html_src, sec_html_dst)
                    self._emit_log(f"[report] Secrets HTML → {sec_html_dst}")
                except Exception as e:
                    self._emit_log(f"[report] secrets HTML copy skipped: {e!r}")
            try:
                sarif_path = export_sarif(out_dir)
                if sarif_path: self._emit_log(f"[report] SARIF: {sarif_path}")
            except Exception as e:
                self._emit_log(f"[report] SARIF export skipped: {e!r}")
            try:
                merged_path = export_merged_json(out_dir)
                if merged_path: self._emit_log(f"[report] merged JSON: {merged_path}")
            except Exception as e:
                self._emit_log(f"[report] merged JSON skipped: {e!r}")

            meta = {
                "generated_at": ctx["generated_at"], "target": ctx["target"], "mode": mode,
                "counts": ctx["counts"], "total": ctx["total"],
                "sca_total": ctx.get("sca_total", 0), "code_total": ctx.get("code_total", 0),
                "dast_total": ctx.get("dast_total", 0), "api_total": ctx.get("api_total", 0),
                "secrets_total": ctx.get("secrets_total", 0), "snyk_version": ctx.get("snyk_version", ""),
                "failed_stages": sorted(failed_stages), "incomplete": bool(failed_stages),
                "servicenow_tickets": ctx.get("servicenow_tickets", []),
            }
            (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
            try:
                rec = update_history_after_scan(reports_root, ctx, meta,
                                                actor=getattr(self, "_user", ""), report_dir=out_dir)
                self._emit_log(f"[history] recorded — remediated {rec.get('remediated_count', 0)}, "
                               f"new {rec.get('introduced_count', 0)}")
            except Exception as e:
                self._emit_log(f"[history] could not update: {e!r}")
            if active_app and active_app.get("id"):
                try:
                    self._inv_store.record_scan(active_app["id"], meta)
                    self._event_queue.put(("inv_refresh", active_app["id"]))
                except Exception as e:
                    self._emit_log(f"[inventory] could not update: {e!r}")

            self._last_context = ctx; self._last_report_dir = out_dir
            self._last_static_report = Path(report_html)
            audit_log.write_event(reports_root, "scan_end", actor=self._user,
                                  app=(active_app.get("name") if active_app else ""),
                                  mode=mode, total=ctx.get("total", 0), counts=ctx.get("counts", {}),
                                  report=str(report_html), lane="static",
                                  failed_stages=sorted(failed_stages), incomplete=bool(failed_stages),
                                  cancelled=self._static_cancel_evt.is_set(), log=self._emit_log)
            self._event_queue.put(("static_results", ctx))

            self._event_queue.put(("report", {"path": str(report_html), "primary": route_total == 1}))
            _snow_tickets = ctx.get("servicenow_tickets") or []
            return {"path": str(target), "scanned": True, "report_path": str(report_html),
                    "counts": dict(ctx.get("counts", {})), "total": ctx.get("total", 0),
                    "ticket": _snow_tickets[0].get("number") if _snow_tickets else None}
        except Exception as e:
            self._emit_log(f"[static] scan failed: {e!r}")
            audit_log.write_event(reports_root, "scan_failed", actor=self._user,
                                  app=(active_app.get("name") if active_app else ""),
                                  mode=mode, lane="static", error=repr(e), log=self._emit_log)
            self._event_queue.put(("static_results", None))
            return {"path": str(target), "scanned": False, "reason": f"error: {e}"}
        finally:

            self._session_end("static")

if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else "."
    st = ensure_git_secrets(print)
    res = scan_path(tgt, print, git_secrets_status=st)
    out = write_secrets_report(res, Path(tgt) / "_secrets_out")
    print("secrets report:", out)
