from __future__ import annotations

# Stage A: bootstrap. Heavy deps are installed at runtime against a live splash
# (see BootSplash / run_boot), then used by the app.
import os, sys, shutil, subprocess
from pathlib import Path

IS_WIN   = os.name == "nt"
IS_MAC   = sys.platform == "darwin"
IS_LINUX = not IS_WIN and not IS_MAC


def _pip(args: list[str], log=None) -> None:
    """pip install --user, streaming output lines to `log`."""
    cmd = [sys.executable, "-m", "pip", "install", "--user",
           "--disable-pip-version-check"] + args

    def _stream(command, env=None):
        proc = subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                encoding="utf-8", errors="replace", bufsize=1)
        for line in iter(proc.stdout.readline, ""):
            line = line.rstrip()
            if line and log:
                try: log(line)
                except Exception: pass
        proc.stdout.close()
        return proc.wait()

    if _stream(cmd) != 0:
        env = os.environ.copy()
        env["PIP_TRUSTED_HOST"] = "pypi.org files.pythonhosted.org pypi.python.org"
        hosts = ["--trusted-host", "pypi.org", "--trusted-host",
                 "files.pythonhosted.org", "--trusted-host", "pypi.python.org"]
        if log: log("pip: retrying via trusted-host (corporate TLS proxy?)")
        if _stream(cmd + hosts, env=env) != 0:
            raise subprocess.CalledProcessError(1, cmd)
    import site
    us = site.getusersitepackages()
    if us not in sys.path:
        sys.path.insert(0, us)


def _ensure(import_name: str, pip_name: str | None = None, log=None) -> None:
    pip_name = pip_name or import_name
    for attempt in range(2):
        try:
            __import__(import_name)
            if log: log(f"{import_name}: already satisfied")
            return
        except ImportError:
            if log: log(f"{import_name}: not found — installing {pip_name}…")
            if attempt == 0:
                _pip(["--upgrade", pip_name], log=log)
            else:
                _pip(["--upgrade", "--force-reinstall", pip_name], log=log)
    __import__(import_name)


# Splash steps: (import_name, pip_name, human label). Kept small on purpose —
# the only hard dependency is pyTenable (which pulls requests/restfly).
_BOOT_DEPS = [
    ("requests",  "requests",  "HTTP client"),
    ("tenable",   "pytenable", "Tenable API client (pyTenable)"),
]
_RUNTIME_READY = False


def _load_runtime(progress=None) -> list[tuple[str, str]]:
    """Ensure dependencies. progress(kind, payload) callback is optional.
    Returns a list of (label, detail) warnings for optional components."""
    global _RUNTIME_READY
    _log_lines: list[str] = []
    _boot_started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _boot_log_path = SCRIPT_DIR / "boot_dependencies.log"

    def _log(text):
        stamp = datetime.now().strftime("%H:%M:%S")
        _log_lines.append(f"[{stamp}] {text}")
        if progress:
            try: progress("log", text)
            except Exception: pass

    _warnings: list[tuple[str, str]] = []

    def _warn(label: str, detail: str):
        _log(f"⚠ {label}: {detail}")
        _warnings.append((label, detail))

    def _flush_log(status: str = "in progress"):
        try:
            header = (f"{APP_BRAND_NAME} — dependency boot log\n"
                      f"Run started : {_boot_started}\n"
                      f"Status      : {status}\n" + ("-" * 60) + "\n")
            _boot_log_path.write_text(header + "\n".join(_log_lines) + "\n", encoding="utf-8")
        except Exception:
            pass

    _flush_log()
    try:
        total = len(_BOOT_DEPS)
        for step, (import_name, pip_name, label) in enumerate(_BOOT_DEPS, start=1):
            if progress: progress("step", (step, total, f"{label} ({import_name})"))
            try:
                _ensure(import_name, pip_name, log=_log)
            except Exception as e:
                # pyTenable is required to scan. If it fails to install we still
                # let the UI open (so the user can read the message), but the
                # scan/connect actions will report the error clearly.
                _warn(label, repr(e))
            _flush_log()
        _RUNTIME_READY = True
        if progress: progress("warn_summary", _warnings)
        _flush_log("done" + (f" with {len(_warnings)} warning(s)" if _warnings else ""))
        return _warnings
    except Exception:
        _flush_log("FAILED")
        raise


# ── Stage B: regular imports (available in stdlib regardless of boot) ──────────
import re as _re
import json
import math as _math
import queue
import threading
import tempfile
import webbrowser
from datetime import datetime
from typing import Optional, Callable, Any

import tkinter as tk
from tkinter import ttk, messagebox, filedialog


# ── Constants ─────────────────────────────────────────────────────────────────
SCRIPT_DIR      = Path(__file__).resolve().parent
APP_BRAND_NAME  = "SecOps Tenable · Banco Base"
# Tenable Vulnerability Management cloud endpoint — same for the whole company.
# (Only China / FedRAMP tenants differ: cloud.tenablecloud.cn / fedcloud.tenable.com)
TENABLE_CLOUD_URL = "https://cloud.tenable.com"
DEFAULT_REPORTS = SCRIPT_DIR / "Reports"
SETTINGS_FILE   = SCRIPT_DIR / ".tenable_scanner_settings.json"

# Fonts (platform-aware) — identical to the Snyk build.
if IS_MAC:     _FUI, _FMONO = "SF Pro Text", "Menlo"
elif IS_LINUX: _FUI, _FMONO = "DejaVu Sans", "DejaVu Sans Mono"
else:          _FUI, _FMONO = "Segoe UI", "Cascadia Mono"

# Palette (Banco Base) — copied verbatim from the Snyk scanner so the two tools
# are visually indistinguishable.
_PALETTE_LIGHT = {
    "bg":        "#f5f6f8", "panel_bg":  "#ffffff", "surface2":  "#eef1f7",
    "accent":    "#F5A800", "accent_hi": "#c48700", "button_fg": "#ffffff",
    "accent2":   "#c8102e", "accent2_hi":"#a00d24",
    "text":      "#0d1b2a", "muted":     "#5a6475", "border":    "#dde2ec",
    "ok":        "#1a7a4a", "err":       "#c8102e", "card_hover":"#eef1f7",
    "pill_run_bg":"#002060","pill_run_fg":"#c0ccee",
    "pill_ok_bg": "#0c4a2b","pill_ok_fg": "#a7f0c8",
    "pill_bad_bg":"#7a0c1c","pill_bad_fg":"#fdb8c0",
    "pill_idle_bg":"#dde2ec","pill_idle_fg":"#5a6475",
}
_PALETTE_DARK = {
    "bg":        "#1a1d23", "panel_bg":  "#23272e", "surface2":  "#2c3038",
    "accent":    "#F5A800", "accent_hi": "#c48700", "button_fg": "#ffffff",
    "accent2":   "#c8102e", "accent2_hi":"#a00d24",
    "text":      "#e8eaf0", "muted":     "#8892a4", "border":    "#383d48",
    "ok":        "#2ecc71", "err":       "#e74c3c", "card_hover":"#2c3038",
    "pill_run_bg":"#0a1840","pill_run_fg":"#7a9cee",
    "pill_ok_bg": "#0a3020","pill_ok_fg": "#5fe0a0",
    "pill_bad_bg":"#4a0a10","pill_bad_fg":"#f08090",
    "pill_idle_bg":"#383d48","pill_idle_fg":"#8892a4",
}
T = dict(_PALETTE_LIGHT)
T["highlight"] = T["accent"]; T["highlight_text"] = T["button_fg"]
T["tree_bg"] = T["panel_bg"]; T["button_hover"] = T["accent_hi"]


def _apply_palette(dark: bool) -> None:
    T.update(_PALETTE_DARK if dark else _PALETTE_LIGHT)
    T["highlight"] = T["accent"]; T["highlight_text"] = T["button_fg"]
    T["tree_bg"] = T["panel_bg"]; T["button_hover"] = T["accent_hi"]


# ── Severity helpers (Tenable uses exactly these five levels) ──────────────────
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
# Tenable returns severity as an int 0–4 in many endpoints:
_SEV_FROM_INT = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


def _sev_norm(s) -> str:
    if isinstance(s, (int, float)):
        return _SEV_FROM_INT.get(int(s), "info")
    s = (str(s) if s is not None else "").strip().lower()
    if s in ("critical", "crit", "4"):           return "critical"
    if s in ("high", "3"):                        return "high"
    if s in ("medium", "med", "moderate", "2"):   return "medium"
    if s in ("low", "1"):                         return "low"
    return "info"


def _ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _detect_user() -> str:
    for k in ("USER", "USERNAME", "LOGNAME"):
        v = os.environ.get(k)
        if v: return v
    return "analyst"


def _report_basename(target: str, template: str) -> str:
    """Report base name: '<template>+<target>_<YYYYMMDD>'."""
    date = datetime.now().strftime("%Y%m%d")
    raw = f"{template}+{target}_{date}"
    return _re.sub(r"[^A-Za-z0-9+\-_.]", "_", raw)[:80]


def _open_path(p) -> None:
    p = str(p)
    try:
        if IS_WIN:   os.startfile(p)                       # noqa
        elif IS_MAC: subprocess.Popen(["open", p])
        else:        subprocess.Popen(["xdg-open", p])
    except Exception:
        webbrowser.open(Path(p).as_uri())


# ══════════════════════════════════════════════════════════════════════════════
#  BACKEND — Tenable integration (no Tk; independently testable)
# ══════════════════════════════════════════════════════════════════════════════
class TenableError(Exception):
    pass


# Scan templates shown as clickable cards on the dashboard. The `tio_uuid` /
# policy names are the well-known Tenable template slugs; for Nessus / sc the
# same human concept maps to the closest available policy.
SCAN_TEMPLATES = [
    ("basic",     "🛰", "Basic Network Scan",  "Full port + vuln\nsweep of the host(s)"),
    ("discovery", "🔎", "Host Discovery",      "Live-host & open-port\nenumeration only"),
    ("advanced",  "⚙", "Advanced Scan",       "Fully configurable\ndeep assessment"),
    ("webapp",    "🌐", "Web Application",     "Crawl & probe a\nweb application"),
    ("malware",   "🦠", "Malware Scan",        "Hash & behaviour\nmalware detection"),
]
_TEMPLATE_LABELS = {k: name for k, _, name, _ in SCAN_TEMPLATES}


class TenableBackend:
    """Thin, defensive wrapper over pyTenable for the three Tenable products.

    Every public method either returns plain Python structures (lists of finding
    dicts, status strings) or raises TenableError with a human message. The GUI
    never imports pyTenable directly — it only talks to this class.
    """

    def __init__(self):
        self.kind: str = "io"          # "io" | "sc" | "nessus"
        self.client = None
        self.connected = False
        self.last_meta: dict = {}

    # ── connection ────────────────────────────────────────────────────────────
    def connect(self, kind: str, *, access_key="", secret_key="",
                url="", username="", password="", ca_bundle="", insecure=False,
                log=None) -> dict:
        """Open a session. Returns a dict of server properties on success."""
        def _l(m):
            if log:
                try: log(m)
                except Exception: pass

        # Resolve the ssl_verify value shared by all three product clients.
        # True (default) = normal verification. A path string = verify against
        # that CA bundle (the correct fix for a corporate TLS-inspecting
        # proxy). False = verification off entirely (logged loudly — this is
        # a deliberate, session-only, never-persisted opt-in).
        ssl_verify: "bool | str" = True
        if insecure:
            ssl_verify = False
            _l("⚠ Connecting with SSL verification DISABLED.")
        elif ca_bundle:
            if not Path(ca_bundle).is_file():
                raise TenableError(f"CA bundle not found: {ca_bundle}")
            ssl_verify = ca_bundle
            _l(f"Connecting with custom CA bundle: {ca_bundle}")

        self.kind = kind
        try:
            if kind == "io":
                from tenable.io import TenableIO
                if not (access_key and secret_key):
                    raise TenableError("Tenable Vulnerability Management (cloud) "
                                       "requires an Access key and a Secret key.")
                cloud_url = TENABLE_CLOUD_URL
                _l(f"Connecting to Tenable VM cloud ({cloud_url})…")
                self.client = TenableIO(access_key, secret_key, url=cloud_url,
                                        vendor="BancoBase", product="SecOpsTenableGUI",
                                        ssl_verify=ssl_verify)
                props = self.client.server.properties()
                self.last_meta = {"product": "Tenable VM (cloud)",
                                  "server": cloud_url.replace("https://", "").rstrip("/"),
                                  "version": props.get("server_version", "?")}
            elif kind == "nessus":
                from tenable.nessus import Nessus
                if not url:
                    raise TenableError("Nessus requires the scanner URL (e.g. https://host:8834).")
                _l(f"Connecting to Nessus at {url}…")
                if access_key and secret_key:
                    self.client = Nessus(url=url, access_key=access_key, secret_key=secret_key,
                                         ssl_verify=ssl_verify)
                else:
                    self.client = Nessus(url=url, username=username, password=password,
                                         ssl_verify=ssl_verify)
                props = self.client.server.properties()
                self.last_meta = {"product": "Nessus", "server": url,
                                  "version": props.get("server_version", "?")}
            elif kind == "sc":
                from tenable.sc import TenableSC
                if not url:
                    raise TenableError("Tenable.sc requires the console URL.")
                _l(f"Connecting to Tenable.sc at {url}…")
                host = url.replace("https://", "").replace("http://", "").rstrip("/")
                if access_key and secret_key:
                    self.client = TenableSC(host, access_key=access_key, secret_key=secret_key,
                                            ssl_verify=ssl_verify)
                else:
                    self.client = TenableSC(host, ssl_verify=ssl_verify)
                    self.client.login(username, password)
                self.last_meta = {"product": "Tenable.sc", "server": host, "version": "?"}
            else:
                raise TenableError(f"Unknown Tenable product '{kind}'.")
        except TenableError:
            raise
        except ImportError as e:
            raise TenableError(f"pyTenable not available ({e}). Reinstall with: "
                               f"pip install --user --upgrade pytenable")
        except Exception as e:
            raise TenableError(f"Connection failed: {e}")

        self.connected = True
        _l(f"Connected — {self.last_meta.get('product')} {self.last_meta.get('version')}")
        return self.last_meta

    def disconnect(self):
        try:
            if self.kind == "sc" and self.client:
                self.client.logout()
        except Exception:
            pass
        self.client = None; self.connected = False

    # ── scanning ──────────────────────────────────────────────────────────────
    def run_scan(self, template: str, targets: list[str], name: str,
                 *, scanner: str = "", log=None, status=None,
                 cancel: Optional[threading.Event] = None) -> list[dict]:
        """Launch a scan, poll to completion and return normalized findings.

        `status(state)` is called with short state strings for the status pill;
        `log(line)` streams human lines to the ACTIVITY LOG; `cancel` aborts the
        poll loop (the remote scan is best-effort stopped). `scanner` (Tenable VM
        cloud only) selects a linked scanner by name or uuid so internal targets
        can be reached; empty means the default cloud sensor.
        """
        def _l(m):
            if log:
                try: log(m)
                except Exception: pass

        def _s(state):
            if status:
                try: status(state)
                except Exception: pass

        if not self.connected:
            raise TenableError("No active Tenable session. Connect first.")

        if self.kind == "io":
            return self._run_io(template, targets, name, _l, _s, cancel, scanner=scanner)
        # sc / nessus share the editor/scans flow closely; route both through a
        # generic path that uses the pyTenable scans interface.
        return self._run_generic(template, targets, name, _l, _s, cancel)

    # Tenable VM cloud (cloud.tenable.com) ------------------------------------
    def _run_io(self, template, targets, name, _l, _s, cancel, scanner=""):
        tio = self.client
        _s("running"); _l(f"Creating scan '{name}' (template: {_TEMPLATE_LABELS.get(template, template)})")
        try:
            create_kw = dict(name=name, template=template, targets=targets)
            if scanner:
                create_kw["scanner"] = scanner
                _l(f"Routing through scanner: {scanner}")
            scan = tio.scans.create(**create_kw)
            scan_id = scan["id"] if isinstance(scan, dict) else scan
            _l(f"Scan created (id={scan_id}); launching…")
            tio.scans.launch(scan_id)
        except Exception as e:
            raise TenableError(f"Could not launch scan: {e}")

        # Poll status.
        import time
        while True:
            if cancel is not None and cancel.is_set():
                _l("Cancel requested — stopping remote scan…")
                try: tio.scans.stop(scan_id)
                except Exception: pass
                raise TenableError("Scan cancelled by user.")
            try:
                st = tio.scans.status(scan_id)
            except Exception as e:
                raise TenableError(f"Status poll failed: {e}")
            _l(f"  status: {st}")
            if str(st).lower() in ("completed", "canceled", "cancelled", "aborted", "stopped"):
                break
            time.sleep(5)

        _l("Scan finished — fetching results…")
        try:
            results = tio.scans.results(scan_id)
        except Exception as e:
            raise TenableError(f"Fetching results failed: {e}")
        findings = self._normalize_io(results)
        _l(f"Parsed {len(findings)} findings.")
        return findings

    @staticmethod
    def _normalize_io(results: dict) -> list[dict]:
        out: list[dict] = []
        for v in (results or {}).get("vulnerabilities", []) or []:
            out.append({
                "host":      v.get("hostname", "—"),
                "plugin_id": v.get("plugin_id", ""),
                "name":      v.get("plugin_name", v.get("plugin_family", "Finding")),
                "severity":  _sev_norm(v.get("severity")),
                "family":    v.get("plugin_family", ""),
                "count":     v.get("count", 1),
                "port":      "",
                "description": "",
                "solution":  "",
            })
        return out

    # Nessus / sc -------------------------------------------------------------
    def _run_generic(self, template, targets, name, _l, _s, cancel):
        client = self.client
        _s("running"); _l(f"Creating scan '{name}' on {self.last_meta.get('product')}")
        import time
        try:
            scan = client.scans.create(name=name, targets=targets)
            scan_id = scan["id"] if isinstance(scan, dict) else scan
            client.scans.launch(scan_id)
        except Exception as e:
            raise TenableError(f"Could not launch scan: {e}")
        while True:
            if cancel is not None and cancel.is_set():
                try: client.scans.stop(scan_id)
                except Exception: pass
                raise TenableError("Scan cancelled by user.")
            try:
                details = client.scans.details(scan_id)
                st = (details.get("info", {}) or {}).get("status", "running")
            except Exception as e:
                raise TenableError(f"Status poll failed: {e}")
            _l(f"  status: {st}")
            if str(st).lower() in ("completed", "canceled", "cancelled", "aborted", "stopped", "imported"):
                break
            time.sleep(5)
        try:
            details = client.scans.details(scan_id)
        except Exception as e:
            raise TenableError(f"Fetching results failed: {e}")
        findings = self._normalize_generic(details)
        _l(f"Parsed {len(findings)} findings.")
        return findings

    @staticmethod
    def _normalize_generic(details: dict) -> list[dict]:
        out: list[dict] = []
        for v in (details or {}).get("vulnerabilities", []) or []:
            out.append({
                "host":      "—",
                "plugin_id": v.get("plugin_id", ""),
                "name":      v.get("plugin_name", "Finding"),
                "severity":  _sev_norm(v.get("severity")),
                "family":    v.get("plugin_family", ""),
                "count":     v.get("count", 1),
                "port":      "",
                "description": "",
                "solution":  "",
            })
        return out


# ── Counts / report helpers (pure, testable) ──────────────────────────────────
def severity_counts(findings: list[dict]) -> dict:
    c = {k: 0 for k in _SEV_RANK}
    for f in findings:
        c[_sev_norm(f.get("severity"))] += 1
    return c


def worst_severity(findings: list[dict]) -> str:
    worst = "info"
    for f in findings:
        s = _sev_norm(f.get("severity"))
        if _SEV_RANK[s] > _SEV_RANK[worst]: worst = s
    return worst


def findings_to_csv(findings: list[dict], path: Path) -> None:
    import csv
    cols = ["host", "severity", "plugin_id", "name", "family", "port", "count"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for f in sorted(findings, key=lambda x: -_SEV_RANK[_sev_norm(x.get("severity"))]):
            w.writerow({c: f.get(c, "") for c in cols})


def findings_to_html(findings: list[dict], path: Path, *, target: str, template: str) -> None:
    """Self-contained Banco-Base-themed HTML report."""
    counts = severity_counts(findings)
    sev_color = {"critical": "#c8102e", "high": "#e0581c", "medium": "#F5A800",
                 "low": "#5a6475", "info": "#8892a4"}
    rows = []
    for f in sorted(findings, key=lambda x: -_SEV_RANK[_sev_norm(x.get("severity"))]):
        sev = _sev_norm(f.get("severity"))
        rows.append(
            f"<tr><td><span class='pill' style='background:{sev_color[sev]}'>{sev.upper()}</span></td>"
            f"<td>{f.get('host','')}</td><td class='mono'>{f.get('plugin_id','')}</td>"
            f"<td>{f.get('name','')}</td><td>{f.get('family','')}</td>"
            f"<td class='mono'>{f.get('port','') or '—'}</td></tr>")
    chips = " ".join(
        f"<span class='chip' style='--c:{sev_color[s]}'>{counts[s]} {s.upper()}</span>"
        for s in ("critical", "high", "medium", "low", "info"))
    html = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>{APP_BRAND_NAME} — {target}</title><style>
:root{{--accent:#F5A800;--navy:#0d1b2a;--muted:#5a6475;--border:#dde2ec;}}
*{{box-sizing:border-box}}body{{font-family:'Segoe UI',system-ui,sans-serif;margin:0;
background:#f5f6f8;color:var(--navy)}}
header{{background:var(--navy);color:#fff;padding:22px 32px;border-top:4px solid var(--accent)}}
header h1{{margin:0;font-size:20px}}header .sub{{color:#b9c2d4;font-size:13px;margin-top:4px}}
.wrap{{max-width:1100px;margin:24px auto;padding:0 24px}}
.chips{{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}}
.chip{{border:1px solid var(--border);border-left:5px solid var(--c);background:#fff;
padding:8px 14px;font-weight:700;font-size:13px;border-radius:4px}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--border)}}
th{{background:var(--accent);color:#fff;text-align:left;padding:9px 12px;font-size:13px}}
td{{padding:9px 12px;border-top:1px solid var(--border);font-size:13px;vertical-align:top}}
tr:hover td{{background:#eef1f7}}.mono{{font-family:'Cascadia Mono',monospace;color:var(--muted)}}
.pill{{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700}}
footer{{color:var(--muted);font-size:12px;text-align:center;padding:24px}}
</style></head><body>
<header><h1>{APP_BRAND_NAME}</h1>
<div class="sub">Target: <b>{target}</b> · Template: <b>{_TEMPLATE_LABELS.get(template, template)}</b>
· Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}</div></header>
<div class="wrap"><div class="chips">{chips}</div>
<table><thead><tr><th>Severity</th><th>Host</th><th>Plugin</th><th>Name</th><th>Family</th><th>Port</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=6>No findings.</td></tr>'}</tbody></table></div>
<footer>{len(findings)} findings · SecOps Tenable · Banco Base</footer></body></html>"""
    path.write_text(html, encoding="utf-8")


# ══════════════════════════════════════════════════════════════════════════════
#  Small themed-widget helper (used in console header)
# ══════════════════════════════════════════════════════════════════════════════
def _themed_btn(parent, text, cmd, *, font, bg, fg, hover_bg, hover_fg, padx=10):
    b = tk.Button(parent, text=text, command=cmd, font=font, bg=bg, fg=fg,
                  activebackground=hover_bg, activeforeground=hover_fg, relief="flat",
                  bd=0, padx=padx, pady=2, cursor="hand2")
    b.bind("<Enter>", lambda e: b.config(bg=hover_bg, fg=hover_fg))
    b.bind("<Leave>", lambda e: b.config(bg=bg, fg=fg))
    return b


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════
class ScannerApp(tk.Tk):
    """SecOps Tenable · Banco Base — same chrome as the Snyk scanner."""

    def __init__(self, boot_warnings: Optional[list[tuple[str, str]]] = None):
        super().__init__()
        self.title(APP_BRAND_NAME)
        self.configure(bg=T["bg"])
        self._user = _detect_user()
        self._boot_warnings = boot_warnings or []
        self.backend = TenableBackend()
        try: self.protocol("WM_DELETE_WINDOW", self._on_app_close)
        except Exception: pass
        try:
            if IS_WIN:   self.state("zoomed")
            elif IS_MAC: self.geometry(f"{self.winfo_screenwidth()}x{self.winfo_screenheight()}+0+0")
            else:        self.attributes("-zoomed", True)
        except Exception:
            self.geometry("1400x900")

        self.fonts = {
            "title": (_FUI, 28, "bold"), "heading": (_FUI, 18, "bold"),
            "sub": (_FUI, 13, "bold"), "body": (_FUI, 12), "small": (_FUI, 11),
            "caption": (_FUI, 10), "mono": (_FMONO, 11), "tab": (_FUI, 11, "bold"),
        }
        # state
        self._event_queue: queue.Queue = queue.Queue()
        self._reports_root = DEFAULT_REPORTS
        self._reports_root.mkdir(exist_ok=True)
        # Persistent per-run log — survives app close, used to prove/debug a
        # scan for the ServiceNow ticket evidence trail. Never receives the
        # access/secret key values, only a masked prefix of the access key.
        self._logs_root = SCRIPT_DIR / "Logs"
        self._logs_root.mkdir(exist_ok=True)
        self._session_log_path = self._logs_root / f"scan_session_{_ts()}.log"
        try:
            self._session_log_path.write_text(
                f"{APP_BRAND_NAME} — session log\n"
                f"Started : {datetime.now():%Y-%m-%d %H:%M:%S}\n"
                f"User    : {self._user}\n" + ("-" * 70) + "\n",
                encoding="utf-8")
        except Exception:
            pass
        self._busy = False
        self._cancel_evt = threading.Event()
        self._console_visible = False
        self._dark_mode = False
        self._active_tab = "scan"
        self._selected_template = "basic"
        self._findings: list[dict] = []
        self._last_report_dir: Optional[Path] = None
        self._stage_cards: dict[str, dict] = {}

        # persistent string vars (survive theme rebuild)
        self._conn_kind   = tk.StringVar(value="io")
        self._v_url       = tk.StringVar()
        self._v_access    = tk.StringVar()
        self._v_secret    = tk.StringVar()
        self._v_scanner   = tk.StringVar()
        self._v_cabundle  = tk.StringVar()
        self._v_insecure  = tk.BooleanVar(value=False)
        self._v_user      = tk.StringVar()
        self._v_pass      = tk.StringVar()
        self._v_targets   = tk.StringVar(value="10.0.4.0/24")
        self._v_scanname  = tk.StringVar(value=f"BancoBase Scan {datetime.now():%Y-%m-%d}")
        self._status_var  = tk.StringVar(value="Idle — not connected.")
        self._sev_filter  = tk.StringVar(value="all")

        self._load_settings()
        self._init_ttk_style()
        self._build_ui()
        self.after(80, self._pump_events)
        self._log(f"Session log → {self._session_log_path}")
        if self._boot_warnings:
            self.after(400, self._show_boot_warnings)

    # ── ttk styling (treeview / scrollbars to match the theme) ────────────────
    def _init_ttk_style(self):
        s = ttk.Style(self)
        try: s.theme_use("clam")
        except tk.TclError: pass
        s.configure("Treeview", background=T["panel_bg"], fieldbackground=T["panel_bg"],
                    foreground=T["text"], rowheight=24, borderwidth=0)
        s.configure("Treeview.Heading", background=T["surface2"], foreground=T["text"],
                    font=(_FUI, 10, "bold"), relief="flat")
        s.map("Treeview.Heading", background=[("active", T["card_hover"])])
        s.map("Treeview", background=[("selected", T["accent"])],
              foreground=[("selected", T["button_fg"])])
        s.configure("TEntry", fieldbackground=T["surface2"], foreground=T["text"])
        s.configure("TCombobox", fieldbackground=T["surface2"], foreground=T["text"])

    # ── top-level build ───────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_ribbon()
        self._build_body()
        self._build_status_bar()
        self._show_tab(self._active_tab)
        self._refresh_connection_state()

    def _rebuild_ui(self):
        """Tear down and rebuild everything (used by the theme toggle). All real
        state lives in self.* / StringVars, so the rebuilt UI is identical."""
        for w in self.winfo_children():
            w.destroy()
        self._stage_cards.clear()
        self._init_ttk_style()
        self._build_ui()
        self._render_findings()

    # ── ribbon ────────────────────────────────────────────────────────────────
    def _build_ribbon(self):
        self._ribbon = tk.Frame(self, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        self._ribbon.pack(side="top", fill="x")
        tk.Frame(self._ribbon, bg=T["accent"], height=2).pack(fill="x", side="top")
        inner_row = tk.Frame(self._ribbon, bg=T["panel_bg"]); inner_row.pack(fill="x", side="top")
        self._ribbon_tabs: dict[str, tk.Button] = {}
        tabs = [("scan", "▶ Scan"), ("connect", "🔌 Connection"),
                ("findings", "📋 Findings"), ("reports", "📄 Reports")]
        tab_area = tk.Frame(inner_row, bg=T["panel_bg"]); tab_area.pack(side="left", fill="y", padx=(10, 0))
        for key, label in tabs:
            btn = tk.Button(tab_area, text=label, command=lambda k=key: self._show_tab(k),
                            bg=T["panel_bg"], fg=T["text"], font=(_FUI, 10, "bold"), relief="flat", bd=0,
                            padx=12, pady=6, cursor="hand2", activebackground=T["card_hover"],
                            activeforeground=T["accent"])
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=T["card_hover"])
                     if b != self._ribbon_tabs.get(self._active_tab) else None)
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg=T["panel_bg"])
                     if b != self._ribbon_tabs.get(self._active_tab) else None)
            btn.pack(side="left", fill="y", padx=1)
            self._ribbon_tabs[key] = btn

        right = tk.Frame(inner_row, bg=T["panel_bg"]); right.pack(side="right", padx=8)
        run_wrap = tk.Frame(right, bg=T["accent"], padx=2, pady=2); run_wrap.pack(side="left", padx=(0, 4))
        self._run_icon_btn = tk.Button(run_wrap, text="▶", font=(_FUI, 14, "bold"), command=self._start_scan,
                                       bg=T["panel_bg"], fg=T["accent"], activebackground=T["surface2"],
                                       activeforeground=T["accent"], relief="flat", bd=0, padx=8, pady=4,
                                       cursor="hand2", disabledforeground=T["muted"])
        self._run_icon_btn.pack(fill="both", expand=True)
        stop_wrap = tk.Frame(right, bg=T["muted"], padx=2, pady=2); stop_wrap.pack(side="left", padx=(0, 8))
        self._stop_icon_btn = tk.Button(stop_wrap, text="■", font=(_FUI, 14, "bold"), command=self._request_cancel,
                                        bg=T["panel_bg"], fg=T["muted"], activebackground=T["surface2"],
                                        activeforeground=T["err"], relief="flat", bd=0, padx=8, pady=4,
                                        cursor="hand2", disabledforeground=T["muted"], state="disabled")
        self._stop_icon_btn.pack(fill="both", expand=True)
        tk.Frame(self._ribbon, bg=T["border"], height=1).pack(fill="x", side="bottom")

    def _show_tab(self, key: str):
        self._active_tab = key
        for k, btn in self._ribbon_tabs.items():
            (btn.config(bg=T["accent"], fg=T["button_fg"]) if k == key
             else btn.config(bg=T["panel_bg"], fg=T["text"]))
        for k, frame in self._tab_frames.items():
            if k == key: frame.tkraise()

    # ── body / tabs ───────────────────────────────────────────────────────────
    def _build_body(self):
        body = tk.Frame(self, bg=T["bg"]); body.pack(side="top", fill="both", expand=True)
        self._console_frame = tk.Frame(body, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        self._build_console(self._console_frame)
        stack = tk.Frame(body, bg=T["bg"]); stack.pack(side="top", fill="both", expand=True)
        self._tab_frames: dict[str, tk.Frame] = {}
        builders = {"scan": self._build_tab_scan, "connect": self._build_tab_connect,
                    "findings": self._build_tab_findings, "reports": self._build_tab_reports}
        for key, builder in builders.items():
            f = tk.Frame(stack, bg=T["bg"]); f.place(x=0, y=0, relwidth=1, relheight=1)
            builder(f); self._tab_frames[key] = f

    def _build_status_bar(self):
        bar = tk.Frame(self, bg=T["panel_bg"], pady=5, highlightthickness=1, highlightbackground=T["border"])
        bar.pack(side="bottom", fill="x")
        self._theme_btn = tk.Button(bar, text=("🌙" if self._dark_mode else "☀"), command=self._toggle_theme,
                                    font=(_FUI, 13), bg=T["panel_bg"], fg=T["muted"], relief="flat",
                                    padx=8, pady=0, cursor="hand2", activebackground=T["card_hover"])
        self._theme_btn.pack(side="left", padx=(8, 0))
        self._console_btn = tk.Button(bar, text="▥  Console", command=self._toggle_console,
                                      font=self.fonts["caption"], bg=T["panel_bg"], fg=T["muted"], relief="flat",
                                      padx=8, pady=0, cursor="hand2", activebackground=T["card_hover"])
        self._console_btn.pack(side="left", padx=8)
        os_tag = "macOS" if IS_MAC else ("Windows" if IS_WIN else "Linux")
        user_box = tk.Frame(bar, bg=T["panel_bg"]); user_box.pack(side="right", padx=10)
        tk.Label(user_box, text=f"  ·  {os_tag}", font=self.fonts["caption"], bg=T["panel_bg"], fg=T["muted"]).pack(side="right")
        tk.Label(user_box, text=f"👤 {self._user}", font=self.fonts["caption"], bg=T["panel_bg"], fg=T["text"]).pack(side="right")
        tk.Label(bar, textvariable=self._status_var, font=self.fonts["caption"],
                 bg=T["panel_bg"], fg=T["accent"], anchor="center").pack(expand=True)

    def _build_console(self, parent):
        hdr = tk.Frame(parent, bg=T["accent"], padx=10, pady=6); hdr.pack(fill="x")
        tk.Label(hdr, text="ACTIVITY LOG", font=(_FUI, 11, "bold"), bg=T["accent"], fg=T["button_fg"]).pack(side="left")
        _themed_btn(hdr, "✕ Close", self._toggle_console, font=self.fonts["small"], bg=T["accent"],
                    fg=T["button_fg"], hover_bg=T["button_hover"], hover_fg=T["button_fg"], padx=8).pack(side="right")
        inner = tk.Frame(parent, bg=T["surface2"]); inner.pack(fill="both", expand=True)
        self._log_widget = tk.Text(inner, wrap="word", font=self.fonts["mono"], bg=T["surface2"], fg=T["text"],
                                   insertbackground=T["text"], relief="flat", padx=12, pady=8, height=10, state="disabled")
        self._log_widget.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(inner, command=self._log_widget.yview); sb.pack(side="right", fill="y")
        self._log_widget.configure(yscrollcommand=sb.set)

    def _toggle_console(self):
        if self._console_visible:
            self._console_frame.pack_forget(); self._console_visible = False
        else:
            self._console_frame.pack(side="bottom", fill="x"); self._console_visible = True
        self._console_btn.configure(fg=T["text"])

    # ── shared UI helpers (copied chrome) ─────────────────────────────────────
    def _scrollable(self, parent, pad=(18, 12, 18, 8)) -> tk.Frame:
        canvas = tk.Canvas(parent, bg=T["bg"], highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True); vsb.pack(side="right", fill="y")
        holder = tk.Frame(canvas, bg=T["bg"])
        win = canvas.create_window((0, 0), window=holder, anchor="nw")
        holder.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win, width=e.width))
        def wheel(e): canvas.yview_scroll(int(-e.delta / 120), "units")
        canvas.bind("<Enter>", lambda _: canvas.bind_all("<MouseWheel>", wheel))
        canvas.bind("<Leave>", lambda _: canvas.unbind_all("<MouseWheel>"))
        inner = tk.Frame(holder, bg=T["bg"], padx=pad[0], pady=pad[1]); inner.pack(fill="both", expand=True)
        return inner

    def _section_header(self, parent, text: str) -> tk.Frame:
        f = tk.Frame(parent, bg=T["panel_bg"], padx=14, pady=6); f.pack(fill="x")
        tk.Label(f, text=text, font=(_FUI, 13, "bold"), bg=T["panel_bg"], fg=T["accent"], anchor="w").pack(side="left")
        return f

    def _card(self, parent, title="", *, pady=(0, 10)) -> tk.Frame:
        outer = tk.Frame(parent, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        outer.pack(fill="x", pady=pady)
        if title:
            hdr = tk.Frame(outer, bg=T["accent"], padx=14, pady=5); hdr.pack(fill="x")
            tk.Label(hdr, text=title, font=(_FUI, 10, "bold"), bg=T["accent"], fg=T["button_fg"], anchor="w").pack(side="left")
        inner = tk.Frame(outer, bg=T["panel_bg"], padx=14, pady=10); inner.pack(fill="both", expand=True)
        return inner

    def _panel(self, parent, title, *, pady=(0, 10)):
        outer = tk.Frame(parent, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        outer.pack(fill="both", expand=True, pady=pady)
        hdr = tk.Frame(outer, bg=T["accent"], padx=14, pady=5); hdr.pack(fill="x")
        tk.Label(hdr, text=title, font=(_FUI, 10, "bold"), bg=T["accent"], fg=T["button_fg"], anchor="w").pack(side="left")
        right = tk.Frame(hdr, bg=T["accent"]); right.pack(side="right")
        self._panel_summary_lbl = tk.Label(right, text="", font=(_FUI, 9, "bold"),
                                            bg=T["accent"], fg=T["button_fg"])
        self._panel_summary_lbl.pack(side="right")
        inner = tk.Frame(outer, bg=T["panel_bg"], padx=14, pady=10); inner.pack(fill="both", expand=True)
        return inner

    def _lbl(self, parent, text="", size=11, bold=False, bg=None, fg=None, **kw) -> tk.Label:
        return tk.Label(parent, text=text, font=(_FUI, size, "bold" if bold else "normal"),
                        bg=bg or T["panel_bg"], fg=fg or T["text"], **kw)

    def _btn(self, parent, text, cmd, kind="accent", **kw) -> tk.Button:
        """Bordered button matching the Snyk scanner: an accent frame wrapping a
        panel-bg button (the 'gold-rimmed' look)."""
        base_pad, base_font = (12, 7), (_FUI, 11, "bold")
        is_ribbon = parent is getattr(self, "_ribbon", None)
        if kind == "accent" and not is_ribbon:
            container = tk.Frame(parent, bg=T["accent"])
            inner = tk.Button(container, text=text, command=cmd, bg=T["panel_bg"], fg=T["accent"],
                              activebackground=T["card_hover"], activeforeground=T["accent_hi"],
                              font=base_font, padx=base_pad[0], pady=base_pad[1],
                              cursor="hand2", bd=0, relief="flat", **kw)
            inner.pack(fill="both", expand=True, padx=1, pady=1)
            inner.pack = lambda *a, **kwa: container.pack(*a, **kwa)
            inner.grid = lambda *a, **kwa: container.grid(*a, **kwa)
            return inner
        kinds = {
            "danger":  dict(bg=T["accent2"], fg=T["button_fg"], activebackground=T["accent2_hi"],
                            activeforeground=T["button_fg"], font=base_font, padx=base_pad[0], pady=base_pad[1]),
            "outline": dict(bg=T["panel_bg"], fg=T["accent"], activebackground=T["card_hover"],
                            activeforeground=T["accent_hi"], font=base_font, padx=base_pad[0],
                            pady=base_pad[1], borderwidth=1, relief="solid"),
            "flat":    dict(bg=T["surface2"], fg=T["text"], activebackground=T["card_hover"],
                            activeforeground=T["accent"], font=(_FUI, 11), padx=10, pady=5),
            "accent":  dict(bg=T["accent"], fg=T["button_fg"], activebackground=T["accent_hi"],
                            activeforeground=T["button_fg"], font=base_font, padx=base_pad[0], pady=base_pad[1]),
        }
        cfg = kinds.get(kind, kinds["flat"])
        cfg.setdefault("relief", "flat")
        return tk.Button(parent, text=text, command=cmd, cursor="hand2", bd=0, **cfg, **kw)

    def _hdiv(self, parent, **pk):
        f = tk.Frame(parent, bg=T["border"], height=1); f.pack(fill="x", **pk); return f

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB: Scan dashboard
    # ══════════════════════════════════════════════════════════════════════════
    def _build_tab_scan(self, parent):
        self._section_header(parent, "▶  Scan Dashboard")
        pad = self._scrollable(parent)

        # Active connection banner
        banner = tk.Frame(pad, bg=T["surface2"], highlightthickness=1, highlightbackground=T["border"])
        banner.pack(fill="x", pady=(0, 8))
        bi = tk.Frame(banner, bg=T["surface2"], padx=14, pady=7); bi.pack(fill="x")
        tk.Label(bi, text="🔌  Connection:", font=(_FUI, 10, "bold"), bg=T["surface2"], fg=T["muted"]).pack(side="left")
        self._conn_banner_lbl = tk.Label(bi, text="Not connected — go to 🔌 Connection",
                                         font=(_FUI, 10), bg=T["surface2"], fg=T["muted"])
        self._conn_banner_lbl.pack(side="left", padx=(8, 0))
        tk.Button(bi, text="🔌 Manage", command=lambda: self._show_tab("connect"),
                  bg=T["surface2"], fg=T["accent"], font=(_FUI, 10), relief="flat", padx=8, cursor="hand2",
                  activebackground=T["card_hover"], activeforeground=T["accent_hi"]).pack(side="right")

        cards_row = tk.Frame(pad, bg=T["bg"]); cards_row.pack(fill="x")

        # LEFT — scan template cards (single-select, mirroring the pipeline cards)
        tpl_outer = tk.Frame(cards_row, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        tpl_outer.pack(side="left", fill="both", expand=True, padx=(0, 6))
        th = tk.Frame(tpl_outer, bg=T["accent"], padx=14, pady=6); th.pack(fill="x")
        tk.Label(th, text="SCAN TEMPLATE", font=(_FUI, 10, "bold"), bg=T["accent"], fg=T["button_fg"]).pack(side="left")
        tk.Label(th, text="Click to select", font=(_FUI, 9), bg=T["accent"], fg=T["button_fg"]).pack(side="right")
        tpl = tk.Frame(tpl_outer, bg=T["panel_bg"], padx=10, pady=10); tpl.pack(fill="both", expand=True)
        tpl.columnconfigure(0, weight=1, uniform="t"); tpl.columnconfigure(1, weight=1, uniform="t")

        for i, (key, icon, name, desc) in enumerate(SCAN_TEMPLATES):
            self._make_template_card(tpl, key, icon, name, desc, i // 2, i % 2)

        # RIGHT — prerequisites (connection status + buttons)
        pre_outer = tk.Frame(cards_row, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        pre_outer.pack(side="left", fill="both", expand=True)
        ph = tk.Frame(pre_outer, bg=T["accent"], padx=14, pady=5); ph.pack(fill="x")
        tk.Label(ph, text="PREREQUISITES", font=(_FUI, 10, "bold"), bg=T["accent"], fg=T["button_fg"]).pack(side="left")
        env = tk.Frame(pre_outer, bg=T["panel_bg"], padx=12, pady=10); env.pack(fill="both", expand=True)

        row = tk.Frame(env, bg=T["panel_bg"]); row.pack(fill="x", pady=2)
        self._conn_dot = tk.Label(row, text="●", font=(_FUI, 12, "bold"), bg=T["panel_bg"], fg=T["muted"], width=2)
        self._conn_dot.pack(side="left")
        self._lbl(row, "Tenable session", size=10, bold=True, width=16, anchor="w").pack(side="left")
        self._conn_detail = self._lbl(row, "…", size=9, fg=T["muted"], anchor="w")
        self._conn_detail.pack(side="left", fill="x", expand=True, padx=(4, 4))
        fix = self._btn(row, "Fix", lambda: self._show_tab("connect"), kind="outline"); fix.pack(side="right")

        self._hdiv(env, pady=(8, 8))
        btns = tk.Frame(env, bg=T["panel_bg"]); btns.pack(fill="x")
        self._btn(btns, "🔄 Re-check", self._refresh_connection_state, kind="outline").pack(side="left")

        # BELOW — targets + scan name + run
        tgt = self._card(pad, "TARGETS & SCAN NAME", pady=(10, 0))
        tgt.columnconfigure(1, weight=1)
        self._lbl(tgt, "Targets (IP / CIDR / host, comma-sep)", size=10, fg=T["muted"], anchor="e").grid(
            row=0, column=0, sticky="e", padx=(0, 8), pady=4)
        ttk.Entry(tgt, textvariable=self._v_targets).grid(row=0, column=1, sticky="ew", pady=4)
        self._lbl(tgt, "Scan name", size=10, fg=T["muted"], anchor="e").grid(
            row=1, column=0, sticky="e", padx=(0, 8), pady=4)
        ttk.Entry(tgt, textvariable=self._v_scanname).grid(row=1, column=1, sticky="ew", pady=4)

        run_row = tk.Frame(pad, bg=T["bg"]); run_row.pack(fill="x", pady=(12, 0))
        self._scan_btn = self._btn(run_row, "▶  Run scan", self._start_scan, kind="accent")
        self._scan_btn.pack(side="left")
        self._cancel_btn = self._btn(run_row, "■  Cancel", self._request_cancel, kind="danger")
        self._cancel_btn.pack(side="left", padx=(8, 0))
        self._cancel_btn.config(state="disabled")
        self._lbl(run_row, "  Selected: ", size=10, fg=T["muted"], bg=T["bg"]).pack(side="left", padx=(16, 0))
        self._sel_tpl_lbl = self._lbl(run_row, _TEMPLATE_LABELS["basic"], size=10, bold=True, bg=T["bg"], fg=T["accent"])
        self._sel_tpl_lbl.pack(side="left")

    def _make_template_card(self, parent, key, icon, name, desc, r, c):
        active = (key == self._selected_template)
        cell = tk.Frame(parent, bg=T["surface2"], highlightthickness=1,
                        highlightbackground=T["border"], cursor="hand2")
        cell.grid(row=r, column=c, padx=4, pady=4, sticky="nsew")
        top = tk.Frame(cell, bg=T["surface2"], padx=8, pady=6); top.pack(fill="x")
        badge = tk.Label(top, text=icon, font=(_FUI, 13), bg=T["accent"], fg=T["button_fg"], padx=6)
        badge.pack(side="left")
        name_lbl = tk.Label(top, text=name, font=(_FUI, 10, "bold"), bg=T["surface2"], fg=T["text"])
        name_lbl.pack(side="left", padx=8)
        desc_lbl = tk.Label(cell, text=desc, font=(_FUI, 8), bg=T["surface2"], fg=T["muted"],
                            anchor="w", justify="left", padx=8)
        desc_lbl.pack(fill="x", pady=(0, 8))
        rec = {"cell": cell, "top": top, "badge": badge, "name": name_lbl, "desc": desc_lbl, "icon": icon}
        self._stage_cards[key] = rec

        def _paint(on):
            if on:
                cell.configure(bg=T["accent"], highlightbackground=T["accent"]); top.configure(bg=T["accent"])
                badge.configure(text="✓", bg="#ffffff", fg=T["accent"])
                name_lbl.configure(bg=T["accent"], fg=T["button_fg"]); desc_lbl.configure(bg=T["accent"], fg=T["button_fg"])
            else:
                cell.configure(bg=T["surface2"], highlightbackground=T["border"]); top.configure(bg=T["surface2"])
                badge.configure(text=icon, bg=T["accent"], fg=T["button_fg"])
                name_lbl.configure(bg=T["surface2"], fg=T["text"]); desc_lbl.configure(bg=T["surface2"], fg=T["muted"])
        rec["paint"] = _paint
        _paint(active)

        def _select(_e=None):
            self._selected_template = key
            for k, r2 in self._stage_cards.items():
                r2["paint"](k == key)
            if hasattr(self, "_sel_tpl_lbl"):
                self._sel_tpl_lbl.config(text=_TEMPLATE_LABELS[key])
            self._save_settings()

        def _enter(_e):
            if key != self._selected_template: cell.configure(highlightbackground=T["accent"])
        def _leave(_e):
            if key != self._selected_template: cell.configure(highlightbackground=T["border"])
        for w in cell.winfo_children() + [cell]:
            w.bind("<Button-1>", _select); w.bind("<Enter>", _enter); w.bind("<Leave>", _leave)

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB: Connection
    # ══════════════════════════════════════════════════════════════════════════
    def _build_tab_connect(self, parent):
        self._section_header(parent, "🔌  Tenable Connection")
        pad = self._scrollable(parent)

        prod = self._card(pad, "PRODUCT")
        self._lbl(prod, "Choose which Tenable product to connect to:", size=10, fg=T["muted"], anchor="w").pack(fill="x")
        radios = tk.Frame(prod, bg=T["panel_bg"]); radios.pack(fill="x", pady=(6, 0))
        for val, label in [("io", "Tenable VM  ·  cloud.tenable.com"),
                           ("nessus", "Nessus  (local scanner)"),
                           ("sc", "Tenable.sc  (on-prem console)")]:
            rb = tk.Radiobutton(radios, text=label, value=val, variable=self._conn_kind,
                                command=self._sync_conn_fields, bg=T["panel_bg"], fg=T["text"],
                                selectcolor=T["surface2"], activebackground=T["panel_bg"],
                                activeforeground=T["accent"], font=(_FUI, 10), anchor="w",
                                highlightthickness=0, bd=0)
            rb.pack(side="left", padx=(0, 18))

        creds = self._card(pad, "CREDENTIALS")
        creds.columnconfigure(1, weight=1)
        self._conn_field_rows = {}

        def field(r, key, label, var, show=None):
            lbl = self._lbl(creds, label, size=10, fg=T["muted"], anchor="e")
            lbl.grid(row=r, column=0, sticky="e", padx=(0, 8), pady=4)
            ent = ttk.Entry(creds, textvariable=var, show=show or "")
            ent.grid(row=r, column=1, sticky="ew", pady=4)
            self._conn_field_rows[key] = (lbl, ent)

        field(0, "url",    "Cloud / console URL", self._v_url)
        field(1, "access", "Access key",            self._v_access)
        field(2, "secret", "Secret key",            self._v_secret, show="•")
        field(3, "scanner","Cloud scanner (internal targets)", self._v_scanner)
        field(4, "user",   "Username (fallback)",   self._v_user)
        field(5, "pass",   "Password (fallback)",   self._v_pass, show="•")

        # Corporate TLS-inspection proxies (common on bank networks) terminate
        # HTTPS with their own self-signed / internal-CA certificate. The fix
        # is to trust THAT certificate explicitly — not to stop verifying
        # certificates altogether. This field is the safe path.
        ca_lbl = self._lbl(creds, "Corporate CA bundle (.pem/.crt)", size=10, fg=T["muted"], anchor="e")
        ca_lbl.grid(row=6, column=0, sticky="e", padx=(0, 8), pady=4)
        ca_row = tk.Frame(creds, bg=T["panel_bg"]); ca_row.grid(row=6, column=1, sticky="ew", pady=4)
        ca_row.columnconfigure(0, weight=1)
        ttk.Entry(ca_row, textvariable=self._v_cabundle).grid(row=0, column=0, sticky="ew")
        self._btn(ca_row, "Browse…", self._pick_ca_bundle, kind="outline").grid(row=0, column=1, padx=(6, 0))
        self._conn_field_rows["cabundle"] = (ca_lbl, ca_row)

        # Explicit, OFF-by-default, never-persisted escape hatch. Every use is
        # logged loudly (GUI + session log file) because it disables MITM
        # protection on a session that carries a live Tenable API key.
        insecure_row = tk.Frame(creds, bg=T["panel_bg"])
        insecure_row.grid(row=7, column=0, columnspan=2, sticky="w", pady=(6, 0))
        tk.Checkbutton(insecure_row, variable=self._v_insecure,
                       text="⚠ Skip certificate verification (insecure — corporate-proxy troubleshooting only)",
                       bg=T["panel_bg"], fg=T["err"], selectcolor=T["surface2"],
                       activebackground=T["panel_bg"], activeforeground=T["err"],
                       font=(_FUI, 9, "bold"), anchor="w", highlightthickness=0, bd=0
                       ).pack(side="left")

        hint = self._lbl(creds, "", size=9, fg=T["muted"], anchor="w", wraplength=620, justify="left")
        hint.grid(row=8, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self._conn_hint = hint

        btns = tk.Frame(pad, bg=T["bg"]); btns.pack(fill="x", pady=(12, 0))
        self._btn(btns, "🔗  Connect", self._do_connect, kind="accent").pack(side="left")
        self._btn(btns, "✖  Disconnect", self._do_disconnect, kind="outline").pack(side="left", padx=(8, 0))

        # live status card
        st = self._card(pad, "STATUS", pady=(12, 0))
        row = tk.Frame(st, bg=T["panel_bg"]); row.pack(fill="x")
        self._conn_status_dot = tk.Label(row, text="●", font=(_FUI, 14, "bold"), bg=T["panel_bg"], fg=T["muted"])
        self._conn_status_dot.pack(side="left", padx=(0, 8))
        self._conn_status_lbl = self._lbl(row, "Not connected.", size=11, fg=T["text"], anchor="w")
        self._conn_status_lbl.pack(side="left")

        self._sync_conn_fields()

    def _sync_conn_fields(self):
        """Show only the fields relevant to the chosen product."""
        kind = self._conn_kind.get()
        relevance = {
            "io":     {"url": False, "access": True,  "secret": True,  "scanner": True,  "user": False, "pass": False},
            "nessus": {"url": True,  "access": True,  "secret": True,  "scanner": False, "user": True,  "pass": True},
            "sc":     {"url": True,  "access": True,  "secret": True,  "scanner": False, "user": True,  "pass": True},
        }[kind]
        if not hasattr(self, "_conn_field_rows"): return
        for key in ("url", "access", "secret", "scanner", "user", "pass"):
            lbl, ent = self._conn_field_rows[key]
            if relevance[key]:
                lbl.grid(); ent.grid()
            else:
                lbl.grid_remove(); ent.grid_remove()
        hints = {
            "io": (f"Generate API keys in Profile → My Profile → API Keys."),
            "nessus": "Use https://host:8834. API keys are preferred; username/password works too.",
            "sc": "Tenable.sc console URL. API keys (access/secret) or username/password login.",
        }
        self._conn_hint.config(text=hints[kind])

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB: Findings
    # ══════════════════════════════════════════════════════════════════════════
    def _build_tab_findings(self, parent):
        self._section_header(parent, "📋  Findings")
        outer = tk.Frame(parent, bg=T["bg"]); outer.pack(fill="both", expand=True, padx=18, pady=(6, 8))

        # severity summary chips + filter
        bar = tk.Frame(outer, bg=T["bg"]); bar.pack(fill="x", pady=(0, 8))
        self._sev_chip_frame = tk.Frame(bar, bg=T["bg"]); self._sev_chip_frame.pack(side="left")
        filt = tk.Frame(bar, bg=T["bg"]); filt.pack(side="right")
        self._lbl(filt, "Filter:", size=10, fg=T["muted"], bg=T["bg"]).pack(side="left", padx=(0, 6))
        cb = ttk.Combobox(filt, textvariable=self._sev_filter, width=12, state="readonly",
                          values=["all", "critical", "high", "medium", "low", "info"])
        cb.pack(side="left"); cb.bind("<<ComboboxSelected>>", lambda e: self._render_findings())
        self._btn(filt, "📄 Export", lambda: self._show_tab("reports"), kind="outline").pack(side="left", padx=(8, 0))

        # grouped tree: host → findings
        panel = tk.Frame(outer, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["accent"])
        panel.pack(fill="both", expand=True)
        tk.Frame(panel, bg=T["accent"], height=2).pack(fill="x", side="top")
        tf = tk.Frame(panel, bg=T["panel_bg"]); tf.pack(fill="both", expand=True)
        cols = ("sev", "plugin", "family", "port")
        self._find_tree = ttk.Treeview(tf, columns=cols, show="tree headings", height=20)
        self._find_tree.heading("#0", text="Host / Finding", anchor="w")
        self._find_tree.column("#0", width=420, stretch=True, anchor="w")
        for c, (txt, w, anc) in zip(cols, [("Severity", 90, "w"), ("Plugin", 90, "w"),
                                           ("Family", 160, "w"), ("Port", 70, "w")]):
            self._find_tree.heading(c, text=txt, anchor=anc); self._find_tree.column(c, width=w, anchor=anc)
        self._find_tree.pack(side="left", fill="both", expand=True)
        ttk.Scrollbar(tf, command=self._find_tree.yview, orient="vertical").pack(side="right", fill="y")
        self._find_tree.tag_configure("group", foreground=T["text"], font=(_FUI, 10, "bold"))
        self._find_tree.tag_configure("crit",  foreground=T["err"])
        self._find_tree.tag_configure("med",   foreground=T["text"])
        self._find_tree.tag_configure("muted", foreground=T["muted"])
        self._render_findings()

    def _sev_leaf_tag(self, sev):
        sev = _sev_norm(sev)
        if sev in ("critical", "high"): return "crit"
        if sev == "medium":             return "med"
        return "muted"

    def _render_findings(self):
        if not hasattr(self, "_find_tree"):
            return
        tree = self._find_tree
        for iid in tree.get_children(): tree.delete(iid)
        # chips
        if hasattr(self, "_sev_chip_frame"):
            for w in self._sev_chip_frame.winfo_children(): w.destroy()
            counts = severity_counts(self._findings)
            chip_color = {"critical": T["err"], "high": "#e0581c", "medium": T["accent"],
                          "low": T["muted"], "info": T["muted"]}
            for s in ("critical", "high", "medium", "low", "info"):
                chip = tk.Frame(self._sev_chip_frame, bg=T["panel_bg"], highlightthickness=1,
                                highlightbackground=T["border"])
                chip.pack(side="left", padx=(0, 6))
                tk.Frame(chip, bg=chip_color[s], width=5).pack(side="left", fill="y")
                tk.Label(chip, text=f" {counts[s]} {s.upper()} ", font=(_FUI, 9, "bold"),
                         bg=T["panel_bg"], fg=T["text"]).pack(side="left", padx=(2, 6), pady=3)

        flt = self._sev_filter.get()
        shown = [f for f in self._findings if flt == "all" or _sev_norm(f.get("severity")) == flt]
        if not shown:
            tree.insert("", "end", text="  No findings — run a scan from the ▶ Scan tab.", tags=("muted",))
            return
        by_host: dict[str, list[dict]] = {}
        for f in shown:
            by_host.setdefault(f.get("host", "—"), []).append(f)
        for host in sorted(by_host):
            items = sorted(by_host[host], key=lambda x: -_SEV_RANK[_sev_norm(x.get("severity"))])
            gw = worst_severity(items)
            p = tree.insert("", "end", text=f"{host}   ({len(items)})",
                            values=(gw.upper(), "", "", ""), tags=("group",), open=False)
            for f in items:
                s = _sev_norm(f.get("severity"))
                tree.insert(p, "end", text="   " + f.get("name", ""),
                            values=(s.upper(), f.get("plugin_id", ""), f.get("family", ""),
                                    f.get("port", "") or "—"),
                            tags=(self._sev_leaf_tag(s),))

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB: Reports
    # ══════════════════════════════════════════════════════════════════════════
    def _build_tab_reports(self, parent):
        self._section_header(parent, "📄  Reports & Export")
        pad = self._scrollable(parent)

        exp = self._card(pad, "EXPORT CURRENT FINDINGS")
        self._lbl(exp, "Save the findings from the most recent scan:", size=10, fg=T["muted"], anchor="w").pack(fill="x")
        row = tk.Frame(exp, bg=T["panel_bg"]); row.pack(fill="x", pady=(8, 0))
        self._btn(row, "🌐  HTML report", lambda: self._export("html"), kind="accent").pack(side="left")
        self._btn(row, "📑  CSV", lambda: self._export("csv"), kind="outline").pack(side="left", padx=(8, 0))
        self._btn(row, "📁  Open reports folder", lambda: _open_path(self._reports_root),
                  kind="outline").pack(side="left", padx=(8, 0))

        hist_outer = tk.Frame(pad, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["accent"])
        hist_outer.pack(fill="both", expand=True, pady=(12, 0))
        tk.Frame(hist_outer, bg=T["accent"], height=2).pack(fill="x", side="top")
        hh = tk.Frame(hist_outer, bg=T["accent"], padx=14, pady=5); hh.pack(fill="x")
        tk.Label(hh, text="REPORT HISTORY", font=(_FUI, 10, "bold"), bg=T["accent"], fg=T["button_fg"]).pack(side="left")
        tf = tk.Frame(hist_outer, bg=T["panel_bg"]); tf.pack(fill="both", expand=True)
        cols = ("when", "kind")
        self._hist_tree = ttk.Treeview(tf, columns=cols, show="tree headings", height=12)
        self._hist_tree.heading("#0", text="Report file", anchor="w")
        self._hist_tree.column("#0", width=520, stretch=True, anchor="w")
        self._hist_tree.heading("when", text="Created"); self._hist_tree.column("when", width=160, anchor="w")
        self._hist_tree.heading("kind", text="Type"); self._hist_tree.column("kind", width=80, anchor="w")
        self._hist_tree.pack(side="left", fill="both", expand=True)
        ttk.Scrollbar(tf, command=self._hist_tree.yview, orient="vertical").pack(side="right", fill="y")

        foot = tk.Frame(pad, bg=T["bg"]); foot.pack(fill="x", pady=(8, 0))
        self._btn(foot, "📂 Open", self._open_selected_report, kind="outline").pack(side="left")
        self._btn(foot, "🗑 Delete", self._delete_selected_report, kind="outline").pack(side="left", padx=(8, 0))
        self._btn(foot, "🔄 Refresh", self._refresh_history, kind="outline").pack(side="left", padx=(8, 0))
        self._refresh_history()

    def _refresh_history(self):
        if not hasattr(self, "_hist_tree"): return
        tree = self._hist_tree
        for iid in tree.get_children(): tree.delete(iid)
        files = sorted(self._reports_root.glob("*.*"), key=lambda p: p.stat().st_mtime, reverse=True)
        for p in files:
            if p.suffix.lower() not in (".html", ".csv"): continue
            when = datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            tree.insert("", "end", iid=str(p), text=p.name, values=(when, p.suffix.lstrip(".").upper()))

    def _selected_report(self) -> Optional[Path]:
        sel = self._hist_tree.selection()
        return Path(sel[0]) if sel else None

    def _open_selected_report(self):
        p = self._selected_report()
        if not p: self._info("Open", "Select a report first."); return
        _open_path(p)

    def _delete_selected_report(self):
        p = self._selected_report()
        if not p: return
        try: p.unlink()
        except Exception as e: self._error("Delete", str(e)); return
        self._refresh_history()

    def _export(self, kind: str):
        if not self._findings:
            self._info("Export", "No findings to export — run a scan first."); return
        target = self._v_targets.get().split(",")[0].strip() or "scan"
        base = _report_basename(target, self._selected_template)
        path = self._reports_root / f"{base}.{kind}"
        try:
            if kind == "csv":
                findings_to_csv(self._findings, path)
            else:
                findings_to_html(self._findings, path, target=self._v_targets.get(),
                                 template=self._selected_template)
        except Exception as e:
            self._error("Export", str(e)); return
        self._log(f"Exported {kind.upper()} report → {path.name}")
        self._refresh_history()
        if kind == "html":
            _open_path(path)

    # ══════════════════════════════════════════════════════════════════════════
    #  Connection actions
    # ══════════════════════════════════════════════════════════════════════════
    def _pick_ca_bundle(self):
        path = filedialog.askopenfilename(
            title="Select the corporate root CA certificate",
            filetypes=[("Certificate files", "*.pem *.crt *.cer"), ("All files", "*.*")])
        if path:
            self._v_cabundle.set(path)

    def _do_connect(self):
        if self._busy: return
        kind = self._conn_kind.get()
        self._set_busy(True, "Connecting…")
        self._log(f"Connecting to {kind}…")
        access_val = self._v_access.get().strip()
        if access_val:
            self._log(f"Access key: {access_val[:6]}… (masked)")
        ca_bundle = self._v_cabundle.get().strip()
        insecure = bool(self._v_insecure.get())
        if insecure:
            self._log("⚠ SSL certificate verification is DISABLED for this session — "
                       "this removes protection against a man-in-the-middle on the "
                       "connection to Tenable. Use only to confirm a corporate TLS "
                       "proxy is the cause, then switch to the CA bundle field instead.")
        elif ca_bundle:
            self._log(f"Using custom CA bundle: {ca_bundle}")

        def work():
            try:
                meta = self.backend.connect(
                    kind, access_key=self._v_access.get().strip(),
                    secret_key=self._v_secret.get().strip(), url=self._v_url.get().strip(),
                    username=self._v_user.get().strip(), password=self._v_pass.get(),
                    ca_bundle=ca_bundle, insecure=insecure,
                    log=lambda m: self._post("log", m))
                self._post("connected", meta)
            except Exception as e:
                self._log_exception_to_file("Connection failed", e)
                self._post("conn_error", str(e))
            finally:
                self._post("busy", (False, None))
        threading.Thread(target=work, daemon=True).start()

    def _do_disconnect(self):
        self.backend.disconnect()
        self._refresh_connection_state()
        self._log("Disconnected.")
        self._status_var.set("Idle — not connected.")

    def _refresh_connection_state(self):
        connected = self.backend.connected
        meta = self.backend.last_meta if connected else {}
        prod = meta.get("product", "")
        if hasattr(self, "_conn_dot"):
            self._conn_dot.config(fg=(T["ok"] if connected else T["muted"]))
            self._conn_detail.config(
                text=(f"{prod} {meta.get('version','')}".strip() if connected else "not connected"))
        if hasattr(self, "_conn_banner_lbl"):
            if connected:
                txt = f"{prod} · {meta.get('server','')}"
                self._conn_banner_lbl.config(text=txt, fg=T["ok"])
            else:
                self._conn_banner_lbl.config(text="Not connected — go to 🔌 Connection", fg=T["muted"])
        if hasattr(self, "_conn_status_dot"):
            self._conn_status_dot.config(fg=(T["ok"] if connected else T["muted"]))
            self._conn_status_lbl.config(
                text=(f"Connected — {prod} {meta.get('version','')}".strip()
                      if connected else "Not connected."))

    # ══════════════════════════════════════════════════════════════════════════
    #  Scan actions
    # ══════════════════════════════════════════════════════════════════════════
    def _start_scan(self):
        if self._busy:
            return
        if not self.backend.connected:
            self._info("Run scan", "Connect to Tenable first (🔌 Connection tab).")
            self._show_tab("connect"); return
        targets = [t.strip() for t in self._v_targets.get().split(",") if t.strip()]
        if not targets:
            self._info("Run scan", "Enter at least one target (IP, CIDR or hostname)."); return
        name = self._v_scanname.get().strip() or f"BancoBase Scan {_ts()}"
        tpl = self._selected_template
        scanner = self._v_scanner.get().strip()
        self._cancel_evt.clear()
        self._set_busy(True, f"Scanning ({_TEMPLATE_LABELS.get(tpl, tpl)})…")
        if not self._console_visible: self._toggle_console()
        self._log(f"── Starting {_TEMPLATE_LABELS.get(tpl, tpl)} against {', '.join(targets)} ──")

        def work():
            try:
                findings = self.backend.run_scan(
                    tpl, targets, name, scanner=scanner,
                    log=lambda m: self._post("log", m),
                    status=lambda s: self._post("scan_state", s),
                    cancel=self._cancel_evt)
                self._post("scan_done", findings)
            except TenableError as e:
                self._log_exception_to_file("Scan failed", e)
                self._post("scan_error", str(e))
            except Exception as e:
                self._log_exception_to_file("Scan failed (unexpected)", e)
                self._post("scan_error", f"Unexpected error: {e}")
            finally:
                self._post("busy", (False, None))
        threading.Thread(target=work, daemon=True).start()

    def _request_cancel(self):
        if self._busy:
            self._cancel_evt.set()
            self._log("Cancel requested…")
            self._status_var.set("Cancelling…")

    def _set_busy(self, busy: bool, status: Optional[str] = None):
        self._busy = busy
        if status is not None: self._status_var.set(status)
        run_state = "disabled" if busy else "normal"
        stop_state = "normal" if busy else "disabled"
        for attr, st in (("_run_icon_btn", run_state), ("_stop_icon_btn", stop_state),
                         ("_scan_btn", run_state), ("_cancel_btn", stop_state)):
            w = getattr(self, attr, None)
            if w is not None:
                try: w.config(state=st)
                except Exception: pass

    # ══════════════════════════════════════════════════════════════════════════
    #  Event pump (thread → Tk)
    # ══════════════════════════════════════════════════════════════════════════
    def _post(self, kind, payload):
        self._event_queue.put((kind, payload))

    def _pump_events(self):
        try:
            while True:
                kind, payload = self._event_queue.get_nowait()
                if kind == "log":
                    self._log(str(payload))
                elif kind == "busy":
                    busy, status = payload
                    self._set_busy(busy, status)
                elif kind == "scan_state":
                    self._status_var.set(f"Scan: {payload}")
                elif kind == "connected":
                    self._refresh_connection_state()
                    self._status_var.set(f"Connected — {payload.get('product','')}")
                    self._log(f"✔ Connected to {payload.get('product','')}.")
                    self._save_settings()
                elif kind == "conn_error":
                    self._refresh_connection_state()
                    self._status_var.set("Connection failed.")
                    self._log(f"✖ Connection failed: {payload}  (traceback → {self._session_log_path.name})")
                    self._error("Connection", str(payload))
                elif kind == "scan_done":
                    self._findings = payload or []
                    self._render_findings()
                    worst = worst_severity(self._findings)
                    self._status_var.set(
                        f"✔ Scan complete — {len(self._findings)} findings (worst: {worst.upper()}).")
                    self._log(f"✔ Scan complete — {len(self._findings)} findings.")
                    self._show_tab("findings")
                    if self._findings:
                        self._auto_export()
                elif kind == "scan_error":
                    self._status_var.set("Scan failed / cancelled.")
                    self._log(f"✖ {payload}  (traceback → {self._session_log_path.name})")
                    if "cancel" not in str(payload).lower():
                        self._error("Scan", str(payload))
        except queue.Empty:
            pass
        self.after(80, self._pump_events)

    def _auto_export(self):
        """Drop an HTML report next to every completed scan automatically."""
        try:
            target = self._v_targets.get().split(",")[0].strip() or "scan"
            path = self._reports_root / f"{_report_basename(target, self._selected_template)}.html"
            findings_to_html(self._findings, path, target=self._v_targets.get(),
                             template=self._selected_template)
            self._last_report_dir = path
            self._log(f"Auto-saved report → {path.name}")
            if hasattr(self, "_hist_tree"): self._refresh_history()
        except Exception as e:
            self._log(f"(auto-export skipped: {e})")

    # ══════════════════════════════════════════════════════════════════════════
    #  Console / popups / theme
    # ══════════════════════════════════════════════════════════════════════════
    def _log(self, text: str):
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {text}"
        try:
            self._log_widget.configure(state="normal")
            self._log_widget.insert("end", line + "\n")
            self._log_widget.see("end")
            self._log_widget.configure(state="disabled")
        except Exception:
            print(text)
        # Persist every line — this is what makes the run auditable after the
        # window is closed (attach to the ServiceNow ticket as evidence).
        try:
            with open(self._session_log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception:
            pass

    def _log_exception_to_file(self, context: str, exc: Exception):
        """Write a full traceback to the session log only (safe to call from a
        background thread — pure file I/O, no Tk widget access)."""
        import traceback
        tb = traceback.format_exc()
        try:
            with open(self._session_log_path, "a", encoding="utf-8") as fh:
                fh.write(f"\n[{datetime.now():%H:%M:%S}] ✖ {context} — full traceback:\n{tb}\n")
        except Exception:
            pass

    def _info(self, title, msg):
        messagebox.showinfo(f"{APP_BRAND_NAME} — {title}", msg, parent=self)

    def _error(self, title, msg):
        messagebox.showerror(f"{APP_BRAND_NAME} — {title}", msg, parent=self)

    def _show_boot_warnings(self):
        lines = "\n".join(f"• {l}: {d}" for l, d in self._boot_warnings)
        self._info("Startup notes",
                   "Some components reported issues while installing:\n\n" + lines +
                   "\n\npyTenable is required to connect and scan. If the connection "
                   "fails, reinstall it (pip install --user --upgrade pytenable) or "
                   "check the corporate TLS proxy.")

    def _toggle_theme(self):
        self._dark_mode = not self._dark_mode
        _apply_palette(self._dark_mode)
        self._save_settings()
        self._rebuild_ui()

    # ══════════════════════════════════════════════════════════════════════════
    #  Settings persistence
    # ══════════════════════════════════════════════════════════════════════════
    def _save_settings(self):
        data = {
            "dark": self._dark_mode, "template": self._selected_template,
            "conn_kind": self._conn_kind.get(), "url": self._v_url.get(),
            "targets": self._v_targets.get(),
            # NOTE: secret key / password are intentionally NOT persisted.
            # NOTE: the "skip verification" checkbox is intentionally NOT
            # persisted either — it must be re-opted-into every session.
            "access": self._v_access.get(), "user": self._v_user.get(),
            "scanner": self._v_scanner.get(), "cabundle": self._v_cabundle.get(),
        }
        try: SETTINGS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception: pass

    def _load_settings(self):
        try:
            data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return
        self._dark_mode = bool(data.get("dark", False))
        if self._dark_mode: _apply_palette(True)
        self._selected_template = data.get("template", "basic")
        self._conn_kind.set(data.get("conn_kind", "io"))
        self._v_url.set(data.get("url", ""))
        self._v_access.set(data.get("access", ""))
        self._v_scanner.set(data.get("scanner", ""))
        self._v_cabundle.set(data.get("cabundle", ""))
        self._v_user.set(data.get("user", ""))
        if data.get("targets"): self._v_targets.set(data["targets"])

    def _on_app_close(self):
        self._save_settings()
        try: self.backend.disconnect()
        except Exception: pass
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
#  BOOT SPLASH (globe) — lighter version of the original
# ══════════════════════════════════════════════════════════════════════════════
class BootSplash(tk.Toplevel):
    def __init__(self, master, modal=False):
        super().__init__(master)
        self.overrideredirect(True)
        self.configure(bg=T["accent"])
        W, H = 560, 300
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        border = tk.Frame(self, bg=T["accent"], padx=2, pady=2); border.pack(fill="both", expand=True)
        content = tk.Frame(border, bg=T["bg"]); content.pack(fill="both", expand=True)

        head = tk.Frame(content, bg=T["bg"], padx=20, pady=14); head.pack(fill="x")
        tk.Label(head, text="🛰  " + APP_BRAND_NAME, font=(_FUI, 15, "bold"),
                 bg=T["bg"], fg=T["accent"]).pack(side="left")
        body = tk.Frame(content, bg=T["bg"], padx=20, pady=6); body.pack(fill="both", expand=True)

        # spinning globe
        GR = 46
        cv = tk.Canvas(body, width=GR*2+24, height=GR*2+24, bg=T["bg"], highlightthickness=0)
        cv.pack(side="left", padx=(0, 18))
        cx = cy = GR + 12
        self._globe_angle = 0.0

        def _draw_globe(angle):
            cv.delete("globe")
            cv.create_oval(cx-GR, cy-GR, cx+GR, cy+GR, outline=T["accent"], width=2, tags="globe")
            for k in range(7):
                a = angle + k * 0.5
                rx = GR * abs(_math.cos(a))
                cv.create_oval(cx-rx, cy-GR, cx+rx, cy+GR, outline=T["border"], tags="globe")
            for k in range(-2, 3):
                yy = cy + k * (GR / 3)
                w = (GR**2 - (yy-cy)**2) ** 0.5 if GR**2 > (yy-cy)**2 else 0
                cv.create_line(cx-w, yy, cx+w, yy, fill=T["border"], tags="globe")

        def _spin():
            if self._done or self._error is not None: return
            self._globe_angle = (self._globe_angle + 0.06) % (2*_math.pi)
            _draw_globe(self._globe_angle); self.after(40, _spin)
        _draw_globe(0.0); self.after(40, _spin)

        right = tk.Frame(body, bg=T["bg"]); right.pack(side="left", fill="both", expand=True)
        self._step_var = tk.StringVar(value="Preparing…")
        tk.Label(right, textvariable=self._step_var, font=(_FUI, 11, "bold"),
                 bg=T["bg"], fg=T["accent"], anchor="w").pack(fill="x")
        st = ttk.Style(self)
        try: st.theme_use("clam")
        except tk.TclError: pass
        st.configure("Splash.Horizontal.TProgressbar", troughcolor=T["surface2"],
                     background=T["accent"], bordercolor=T["border"])
        self._pb = ttk.Progressbar(right, style="Splash.Horizontal.TProgressbar",
                                   mode="determinate", maximum=100)
        self._pb.pack(fill="x", pady=(6, 10))
        logwrap = tk.Frame(right, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        logwrap.pack(fill="both", expand=True)
        self._log = tk.Text(logwrap, bg=T["panel_bg"], fg=T["muted"], relief="flat", font=(_FMONO, 9),
                            padx=10, pady=8, height=7, state="disabled", wrap="none")
        self._log.tag_configure("warn", foreground=T["accent"])
        self._log.tag_configure("err", foreground=T["err"])
        self._log.pack(fill="both", expand=True)

        self._q: queue.Queue = queue.Queue()
        self._done = False
        self._error: Optional[str] = None
        self._warnings: list[tuple[str, str]] = []
        self.after(60, self._pump)

    def progress(self, kind, payload):
        self._q.put((kind, payload))

    def _append(self, text, tag=None):
        self._log.configure(state="normal")
        start = self._log.index("end-1c")
        self._log.insert("end", text.rstrip() + "\n")
        if tag: self._log.tag_add(tag, start, "end-1c")
        self._log.see("end"); self._log.configure(state="disabled")

    def _pump(self):
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "step":
                    i, total, label = payload
                    self._step_var.set(f"[{i}/{total}]  {label}")
                    self._pb.configure(value=int(i / max(total, 1) * 100))
                elif kind == "log":
                    text = str(payload)
                    tag = ("err" if text.startswith(("FATAL", "ERROR")) else
                           "warn" if text.startswith("⚠") else None)
                    self._append(text, tag)
                elif kind == "warn_summary":
                    self._warnings = list(payload)
                elif kind == "error":
                    self._error = str(payload)
                elif kind == "done":
                    self._step_var.set(
                        f"⚠ Ready with {len(self._warnings)} note(s)" if self._warnings
                        else "✔ Ready — launching…")
                    self._pb.configure(value=100); self._done = True
        except queue.Empty:
            pass
        if self._done or self._error is not None:
            delay = 1500 if (self._done and self._warnings) else 250
            self.after(delay, self.destroy); return
        self.after(60, self._pump)


def run_boot(master=None):
    own_root = master is None
    if own_root:
        master = tk.Tk(); master.withdraw()
    splash = BootSplash(master, modal=not own_root)
    holder = {"error": None, "warnings": []}

    def worker():
        try:
            result = _load_runtime(progress=splash.progress)
        except Exception as e:
            import traceback
            holder["error"] = f"{e!r}\n\n{traceback.format_exc()}"
            splash.progress("log", f"ERROR: {e!r}")
            splash.progress("error", str(e))
        else:
            holder["warnings"] = result or []
            splash.progress("done", None)

    threading.Thread(target=worker, daemon=True).start()
    master.wait_window(splash)
    if own_root:
        try: master.destroy()
        except Exception: pass
    return holder["error"], holder["warnings"]


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    err, boot_warnings = run_boot()
    if err:
        msg = ("Scanner could not install its dependencies:\n\n" + err +
               "\n\npyTenable is required to connect to Tenable. This is usually a "
               "missing package or a corporate TLS proxy. The window will still open "
               "so you can read this, but scanning won't work until pyTenable installs.")
        try:
            root = tk.Tk(); root.withdraw()
            messagebox.showerror(f"{APP_BRAND_NAME} — startup", msg)
            root.destroy()
        except Exception:
            print(msg, file=sys.stderr)
        # Don't abort — let the user open the app and read the message.
    try:
        app = ScannerApp(boot_warnings=boot_warnings)
    except Exception as e:
        import traceback
        msg = f"Scanner could not start:\n\n{e!r}\n\n" + traceback.format_exc()
        try:
            root = tk.Tk(); root.withdraw()
            messagebox.showerror(f"{APP_BRAND_NAME} — startup failed", msg)
        except Exception:
            print(msg, file=sys.stderr)
        raise
    app.mainloop()


if __name__ == "__main__":
    main()
