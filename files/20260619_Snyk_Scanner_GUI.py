from __future__ import annotations

# Stage A: bootstrap. Heavy deps are installed at runtime against a live splash
# (see BootSplash / run_boot), then the engine modules are imported.
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

    def _drop():
        for m in list(sys.modules):
            if (m == import_name or m.startswith(import_name + ".")
                    or m == "markupsafe" or m.startswith("markupsafe.")):
                sys.modules.pop(m, None)

    for attempt in range(2):
        try:
            __import__(import_name)
            if log: log(f"{import_name}: already satisfied")
            return
        except ImportError as e:
            msg = str(e).lower()
            if log: log(f"{import_name}: not found — installing {pip_name}…")
            if import_name == "jinja2" and ("soft_unicode" in msg or "markupsafe" in msg):
                _pip(["--upgrade", "--force-reinstall", "Jinja2>=3.1", "MarkupSafe>=2.1"], log=log)
            elif attempt == 0:
                _pip(["--upgrade", pip_name], log=log)
            else:
                _pip(["--upgrade", "--force-reinstall", pip_name], log=log)
            _drop()
    __import__(import_name)


# NOTE: Snyk CLI installation used to be duplicated here (a GitHub-release
# binary downloader) *and* in static_scanner.install_snyk() (npm/brew/winget/
# standalone-binary). Consolidated: static_scanner.install_snyk() is now the
# single installer, called from _load_runtime() below (boot) and reused by
# ScannerApp._fix() (re-runs the whole boot splash instead of installing
# inline), so every dependency install — pip packages, Node/npm, git-secrets,
# Snyk CLI — always happens in the one BootSplash window (the globe splash).


# Splash steps: (import_name, pip_name, human label)
_BOOT_DEPS = [
    ("jinja2",            "Jinja2",            "Report templating engine"),
    ("selenium",          "selenium",          "Browser automation (DAST)"),
    ("webdriver_manager", "webdriver-manager", "WebDriver downloader"),
    ("pynput",            "pynput",            "Global hotkey listener (recorder)"),
    ("yaml",              "PyYAML",            "OpenAPI/Swagger YAML spec parsing"),
    ("requests",          "requests",          "HTTP client"),
]
_RUNTIME_READY = False


def _load_runtime(progress=None) -> list[tuple[str, str]]:
    """Ensure heavy deps + Node.js/npm + git-secrets + snyk CLI, then import engine
    modules into this module's namespace. `progress(kind, payload)` callback is optional.
    Returns a list of (label, detail) warnings for optional components that
    couldn't be installed/verified (Node/npm, git-secrets, Snyk CLI) — these
    never abort the boot, they're just surfaced so the user notices instead of
    discovering it later when a scan stage silently fails.

    Every line logged during this boot is also mirrored to a plain-text log file
    next to this script (``boot_dependencies.log``), overwritten on every launch,
    so dependency-install problems can be diagnosed after the splash closes."""
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

    # Optional components (Node/npm, git-secrets, Snyk CLI) never abort the
    # boot on failure — the app can still run without them, just with that
    # one capability disabled. They used to fail *silently* (a line buried in
    # the scrolling log). `_warn` logs the line as before but also tags it as
    # a warning so the splash can flag it visibly (colored log line) and so
    # the finished app can surface a one-time "N install issues" notice.
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
            pass  # logging the boot must never crash the boot itself

    _flush_log()
    try:
        total = len(_BOOT_DEPS) + 4
        step = 0
        for import_name, pip_name, label in _BOOT_DEPS:
            step += 1
            if progress: progress("step", (step, total, f"{label} ({import_name})"))
            _ensure(import_name, pip_name, log=_log)
            _flush_log()

        step += 1
        if progress: progress("step", (step, total, "Node.js + npm (JS runtime)"))
        try:
            import static_scanner
            if static_scanner.check_node().ok and static_scanner.check_npm().ok:
                _log("node/npm: already satisfied")
            else:
                static_scanner.install_node(log=_log)
                if not (static_scanner.check_node().ok and static_scanner.check_npm().ok):
                    _warn("Node.js / npm", "install could not be verified — check the log")
        except Exception as e:
            _warn("Node.js / npm", repr(e))
        _flush_log()

        step += 1
        if progress: progress("step", (step, total, "git-secrets (secret scanner)"))
        try:
            import static_scanner
            static_scanner.ensure_git_secrets(log=_log)
        except Exception as e:
            _warn("git-secrets", repr(e))
        _flush_log()

        step += 1
        if progress: progress("step", (step, total, "Snyk CLI (vulnerability scanner)"))
        try:
            import static_scanner
            if static_scanner.check_snyk().ok:
                _log("snyk-cli: already satisfied")
            else:
                static_scanner.install_snyk(log=_log)
                if not static_scanner.check_snyk().ok:
                    _warn("Snyk CLI", "install could not be verified — check the log")
        except Exception as e:
            _warn("Snyk CLI", repr(e))
        _flush_log()

        step += 1
        if progress: progress("step", (step, total, "Loading scanner engine…"))
        g = globals()
        # SCA + SAST + Secrets now live in one fused module (static_scanner).
        import static_scanner as _ss
        for n in ("CheckResult", "check_python", "check_node", "check_npm",
                  "check_snyk", "check_auth", "install_node", "install_snyk",
                  "start_snyk_auth", "run_snyk_test", "run_snyk_code",
                  "clear_snyk_credentials",
                  "SnykScanError", "ensure_snyk_ready", "setup_proxy_tls_env",
                  "export_sarif", "export_merged_json",
                  "scan_path", "write_secrets_report", "ensure_git_secrets",
                  "get_git_secrets_status", "get_engine_label",
                  "_which", "_run"):
            g[n] = getattr(_ss, n)
        g["static_scanner"] = _ss
        g["secrets_scanner"] = _ss  # backward-compat alias
        import dast_api as _dast
        for n in ("DastConfig", "ApiConfig", "run_dast", "run_api", "_make_driver",
                  "_MACRO_JS", "_MACRO_DRAIN_JS", "_LOGOUT_CAPTURE_JS", "detect_browsers",
                  "_replay_login_macro", "analyze_login_macro", "prewarm_driver",
                  "record_macro_work", "record_logout_work", "test_logout_work",
                  "_api_load_spec", "_api_base_url", "_api_operations", "_make_opener"):
            g[n] = getattr(_dast, n)
        import report_engine as _rep
        for n in ("build_cumulative_context", "export_csv", "render_html",
                  "update_history_after_scan", "render_remediation_history",
                  "add_remediation_action", "load_history", "ScanStateStore"):
            g[n] = getattr(_rep, n)
        _wire_mixin_globals()
        _RUNTIME_READY = True
        _log("Runtime ready.")
        _flush_log("completed successfully" if not _warnings else f"completed with {len(_warnings)} warning(s)")
        if _warnings and progress:
            try: progress("warn_summary", list(_warnings))
            except Exception: pass
        return list(_warnings)
    except Exception as e:
        _log(f"FATAL: {e!r}")
        _flush_log("failed")
        raise


# Stage B: regular imports (stdlib + tkinter, always available).
import json, queue, getpass, re as _re, threading, time, webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Callable, Optional

import tkinter as tk
from tkinter import ttk, messagebox, filedialog


def _open_path(path) -> None:
    """Open a folder/file with the OS default handler."""
    p = str(path)
    try:
        if IS_WIN:    os.startfile(p)  # type: ignore[attr-defined]
        elif IS_MAC:  subprocess.Popen(["open", p])
        else:         subprocess.Popen(["xdg-open", p])
    except Exception:
        try: webbrowser.open(Path(p).as_uri())
        except Exception: pass


def _detect_user() -> str:
    """Best-effort current-user detection (whoami-style)."""
    for getter in (lambda: getpass.getuser(),
                   lambda: os.environ.get("USER") or os.environ.get("USERNAME") or os.environ.get("LOGNAME")):
        try:
            name = getter()
            if name: return str(name)
        except Exception:
            pass
    try:
        out = subprocess.run(["whoami"], capture_output=True, text=True, timeout=4)
        name = (out.stdout or "").strip()
        if name: return name.split("\\")[-1]
    except Exception:
        pass
    return "user"


# Constants
SCRIPT_DIR         = Path(__file__).resolve().parent
APP_BRAND_NAME      = "SecDevOps Banco Base"
DEFAULT_TARGET     = SCRIPT_DIR / "Vulnerable"
DEFAULT_REPORTS    = SCRIPT_DIR / "Reports"
SETTINGS_FILE      = SCRIPT_DIR / ".scanner_settings.json"
# Written while a scan is in flight; its presence at startup means the previous
# run was killed/closed mid-scan (it's deleted on clean completion).
SESSION_FILE       = SCRIPT_DIR / ".scanner_session.json"
AUTH_POLL_INTERVAL = 2
AUTH_POLL_TIMEOUT  = 300

# Fonts (platform-aware)
if IS_MAC:     _FUI, _FMONO = "SF Pro Text", "Menlo"
elif IS_LINUX: _FUI, _FMONO = "DejaVu Sans", "DejaVu Sans Mono"
else:          _FUI, _FMONO = "Segoe UI", "Cascadia Mono"

# Palette (Banco Base)
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

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _sev_norm(s) -> str:
    s = (str(s) if s is not None else "").strip().lower()
    if s in ("critical", "crit"):          return "critical"
    if s == "high":                        return "high"
    if s in ("medium", "med", "moderate"): return "medium"
    if s == "low":                         return "low"
    return "info"


def _kill_process_tree(proc: Optional[subprocess.Popen]) -> None:
    """Forcefully kill `proc` and anything it spawned.

    A plain terminate() only signals the process we directly launched. If
    start_snyk_auth() runs the CLI through an npm/npx wrapper (common when
    Snyk is installed via npm rather than the standalone binary), the actual
    `snyk` process is a *child* of that wrapper and can survive terminate()
    — left running, it keeps holding the Snyk credentials file lock, which
    is exactly what made check_auth() (and the whole login flow) appear to
    hang indefinitely even after the user tried to cancel.
    """
    if proc is None:
        return
    pid = proc.pid
    try:
        if IS_WIN:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                           capture_output=True, timeout=5)
        else:
            # Best-effort: kill direct children first, then the process
            # itself. Deliberately not using killpg here — we don't control
            # how the child was spawned, and killing our own process group
            # by mistake would take the whole app down with it.
            try:
                out = subprocess.run(["pgrep", "-P", str(pid)],
                                     capture_output=True, text=True, timeout=3)
                for child_pid in out.stdout.split():
                    try: os.kill(int(child_pid), 9)
                    except Exception: pass
            except Exception:
                pass
            try: proc.kill()
            except Exception: pass
    except Exception:
        try: proc.kill()
        except Exception: pass
    try: proc.wait(timeout=3)
    except Exception: pass


def _ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _report_basename(user: str, mode: str) -> str:
    """Build the report file base name: '<service>+<user>_<YYYYMMDD>'.
    `mode` is the scan-type/service combination (e.g. 'secrets' or 'code+sca')."""
    date = datetime.now().strftime("%Y%m%d")
    raw = f"{mode}+{user}_{date}"
    return _re.sub(r"[^A-Za-z0-9+\-_]", "_", raw)


def _find_report_html(d) -> Optional[Path]:
    """Return the main HTML report inside a report folder, supporting both the
    new '<service>+<user>_<date>.html' naming and the legacy 'report.html'."""
    d = Path(d)
    if not d.is_dir():
        return None
    legacy = d / "report.html"
    if legacy.exists():
        return legacy
    cands = [p for p in d.glob("*.html")
             if p.name != "remediation_history.html" and not p.name.endswith("_secrets.html")]
    if cands:
        return max(cands, key=lambda p: p.stat().st_mtime)
    return None


# Theme role maps (old colour -> palette role) used by _recolour_widget.
_ROLE_BG = {_PALETTE_LIGHT[k]: k for k in ("bg", "panel_bg", "surface2")}
_ROLE_BG.update({_PALETTE_DARK[k]: k for k in ("bg", "panel_bg", "surface2")})
_ROLE_FG = {_PALETTE_LIGHT[k]: k for k in ("text", "muted", "ok")}
_ROLE_FG.update({_PALETTE_DARK[k]: k for k in ("text", "muted", "ok")})
_ROLE_BTN_BG = {_PALETTE_LIGHT[k]: k for k in ("panel_bg", "surface2")}
_ROLE_BTN_BG.update({_PALETTE_DARK[k]: k for k in ("panel_bg", "surface2")})
_ROLE_ACCENT = {_PALETTE_LIGHT[k]: k for k in ("accent", "accent2")}
_ROLE_ACCENT.update({_PALETTE_DARK[k]: k for k in ("accent", "accent2")})
_BORDERS = (_PALETTE_LIGHT["border"], _PALETTE_DARK["border"])


def _apply_palette(dark: bool) -> None:
    T.update(_PALETTE_DARK if dark else _PALETTE_LIGHT)
    T["highlight"] = T["accent"]; T["highlight_text"] = T["button_fg"]
    T["tree_bg"] = T["panel_bg"]; T["button_hover"] = T["accent_hi"]


def _fill_tree_row(tree: "ttk.Treeview", d: Path, app: Optional[str] = None,
                   filter_text: str = "") -> bool:
    meta: dict = {}
    mf = d / "meta.json"
    if mf.exists():
        try: meta = json.loads(mf.read_text(encoding="utf-8"))
        except Exception: pass
    counts = meta.get("counts") or {}
    vals = (
        meta.get("generated_at") or d.name.replace("report_", ""),
        meta.get("mode", "?"), meta.get("total", "?"),
        counts.get("critical", "?"), counts.get("high", "?"),
        counts.get("medium", "?"), counts.get("low", "?"), meta.get("target", ""))
    if app is not None:
        vals = (app,) + vals
    if filter_text:
        haystack = " ".join(str(v) for v in vals).lower()
        if filter_text.lower().strip() not in haystack:
            return False
    tree.insert("", "end", iid=str(d), values=vals)
    return True


def _make_tree(parent, cols, headings, height) -> "ttk.Treeview":
    outer = tk.Frame(parent, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["accent"])
    outer.pack(side="left", fill="both", expand=True)
    tk.Frame(outer, bg=T["accent"], height=2).pack(fill="x", side="top")
    tf = tk.Frame(outer, bg=T["panel_bg"]); tf.pack(fill="both", expand=True)
    tree = ttk.Treeview(tf, columns=cols, show="headings", height=height)
    for c, (txt, w) in zip(cols, headings):
        tree.heading(c, text=txt); tree.column(c, width=w, anchor="w")
    tree.pack(side="left", fill="both", expand=True)
    ttk.Scrollbar(tf, command=tree.yview, orient="vertical").pack(side="right", fill="y")
    return tree


def _tree_selected_dir(tree: "ttk.Treeview") -> Optional[Path]:
    """Report folder currently selected in a reports Treeview (used by both
    the Recent Scans card and the ReportsViewer popup)."""
    sel = tree.selection()
    return Path(sel[0]) if sel else None


def _delete_selected_report(app, tree: "ttk.Treeview", *on_done: Callable[[], None]) -> None:
    """Delete the report folder selected in `tree`, then run `on_done`
    refresh callbacks. Shared by the Recent Scans card and ReportsViewer so
    both keep one copy of the delete + error-handling behaviour."""
    d = _tree_selected_dir(tree)
    if not d: return
    try:
        shutil.rmtree(d)
    except Exception as e:
        app._show_error_popup("Delete", f"Failed:\n{e}"); return
    for cb in on_done: cb()


def _open_selected_report_folder(app, tree: "ttk.Treeview") -> None:
    """Open the folder of the report selected in `tree` (never the reports
    root) — shared by the Recent Scans card and ReportsViewer."""
    d = _tree_selected_dir(tree)
    if not d:
        app._show_info_popup("Open Folder", "Select a report first."); return
    _open_path(d)


def _center_over(master, win, w_pct: float, h_pct: float) -> None:
    """Size and centre *win* using percentages of the screen."""
    master.update_idletasks()
    sw, sh = master.winfo_screenwidth(), master.winfo_screenheight()
    w, h = int(sw * w_pct), int(sh * h_pct)
    win.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")


def _popup_follow_parent(win: tk.Toplevel, parent: tk.Misc) -> dict:
    """Keep an overrideredirect popup above *parent* across alt-tab cycles.
    On Windows, re-establish the Win32 owner that overrideredirect drops; on all
    platforms, lift on focus and withdraw/restore with the parent. Returns the
    {event: bind_id} map for cleanup."""
    if IS_WIN:
        try:
            import ctypes
            win.update_idletasks()
            child_hwnd  = int(win.wm_frame(), 16)
            parent_hwnd = int(parent.wm_frame(), 16)
            ctypes.windll.user32.SetWindowLongPtrW(child_hwnd, -8, parent_hwnd)
        except Exception:
            pass

    def _on_focus(e):
        if win.winfo_exists():
            try: win.lift()
            except Exception: pass

    def _on_unmap(e):
        if e.widget is parent and win.winfo_exists():
            try: win.withdraw()
            except Exception: pass

    def _on_map(e):
        if e.widget is parent and win.winfo_exists():
            try: win.deiconify(); win.lift()
            except Exception: pass

    return {"<FocusIn>": parent.bind("<FocusIn>", _on_focus, "+"),
            "<Unmap>":   parent.bind("<Unmap>",   _on_unmap, "+"),
            "<Map>":     parent.bind("<Map>",      _on_map,   "+")}


def _themed_btn(parent, text, cmd, *, font, bg, fg, hover_bg, hover_fg, **kw):
    """A flat hand2 tk.Button used by ReportsViewer header/footer rows."""
    return tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg,
                     activebackground=hover_bg, activeforeground=hover_fg,
                     font=font, relief="flat", cursor="hand2", bd=0, **kw)


class ReportsViewer(tk.Toplevel):
    def __init__(self, master, root_path: Path):
        super().__init__(master)
        self._root_path = root_path
        self._app = master
        self.transient(master)
        _center_over(master, self, 0.75, 0.75)
        self.overrideredirect(True)
        self.update_idletasks(); self.lift(); self.focus_force()
        try: self.grab_set()
        except tk.TclError: pass
        _bind_ids: dict = {}

        def _close():
            try: self.grab_release()
            except Exception: pass
            for evt, bid in _bind_ids.items():
                try: master.unbind(evt, bid)
                except Exception: pass
            self.destroy()
            try: master.focus_force()
            except Exception: pass

        self.bind("<Escape>", lambda e: _close())
        _bind_ids.update(_popup_follow_parent(self, master))
        border = tk.Frame(self, bg=T["accent"], padx=2, pady=2); border.pack(fill="both", expand=True)
        content = tk.Frame(border, bg=T["bg"]); content.pack(fill="both", expand=True)

        hb = T["panel_bg"]
        hdr = tk.Frame(content, bg=hb, padx=30, pady=14); hdr.pack(fill="x")
        row = tk.Frame(hdr, bg=hb); row.pack(fill="x")
        xbtn = tk.Label(row, text="✕", font=(_FUI, 13, "bold"), bg=hb, fg=T["muted"], cursor="hand2", padx=6)
        xbtn.pack(side="right")
        xbtn.bind("<Button-1>", lambda e: _close())
        xbtn.bind("<Enter>", lambda e: xbtn.config(fg=T["err"]))
        xbtn.bind("<Leave>", lambda e: xbtn.config(fg=T["muted"]))
        tk.Label(row, text="📋  Report History", font=(_FUI, 15, "bold"), bg=hb, fg=T["accent"]).pack(side="left")
        tk.Label(row, text=str(root_path), font=(_FUI, 10, "italic"), bg=hb, fg=T["muted"]).pack(side="left", padx=(12, 0))
        search_row = tk.Frame(hdr, bg=hb); search_row.pack(fill="x", pady=(10, 0))
        tk.Label(search_row, text="🔎", font=(_FUI, 11), bg=hb, fg=T["muted"]).pack(side="left")
        self._filter_var = tk.StringVar(value="")
        search_entry = ttk.Entry(search_row, textvariable=self._filter_var, width=40)
        search_entry.pack(side="left", padx=(6, 0))
        tk.Label(search_row, text="filter by app, mode, or target — matches as you type",
                 font=(_FUI, 9), bg=hb, fg=T["muted"]).pack(side="left", padx=(8, 0))
        self._filter_var.trace_add("write", lambda *_: self._refresh())
        tk.Frame(content, bg=T["border"], height=1).pack(fill="x")

        tree_wrap = tk.Frame(content, bg=T["bg"]); tree_wrap.pack(fill="both", expand=True, padx=18, pady=(14, 6))
        cols = ("app", "when", "mode", "total", "critical", "high", "medium", "low", "target")
        self._tree = _make_tree(tree_wrap, cols, [
            ("App", 130), ("Generated", 150), ("Mode", 80), ("Total", 55), ("Crit", 45),
            ("High", 45), ("Med", 45), ("Low", 45), ("Target", 300)], height=16)
        self._tree.bind("<Double-1>", lambda _: self._open_html())

        tk.Frame(content, bg=T["border"], height=1).pack(fill="x")
        foot = tk.Frame(content, bg=T["panel_bg"], padx=20, pady=10); foot.pack(fill="x")
        self._app._btn(foot, "✕  Close", _close, kind="accent").pack(side="right", padx=(6, 0))
        for txt, cmd in [("🗑 Delete", self._delete), ("🧬 Export SARIF…", self._export_sarif),
                         ("💾 Export CSV…", self._export_csv), ("📁 Open folder", self._open_selected),
                         ("▶ Open HTML", self._open_html)]:
            self._app._btn(foot, txt, cmd, kind="flat").pack(side="left", padx=(0, 6))
        self._refresh()

    def _scan_dirs(self) -> list[tuple[Path, dict, str]]:
        """Collect report folders across every app profile under the root.
        Report folders live at <root>/<app>/report_*, with legacy ones possibly
        directly under <root>/report_*. Returns (dir, meta, app_label) tuples
        sorted newest-first."""
        root = self._root_path
        if not root.exists():
            return []
        found: list[tuple[Path, str]] = []
        try:
            entries = sorted(root.iterdir())
        except OSError:
            return []
        for entry in entries:
            if not entry.is_dir():
                continue
            if entry.name.startswith("report_"):
                found.append((entry, "—"))  # legacy report directly under root
                continue
            app_label = "(none)" if entry.name == "_unscoped" else entry.name
            try:
                for d in entry.iterdir():
                    if d.is_dir() and d.name.startswith("report_"):
                        found.append((d, app_label))
            except OSError:
                continue
        found.sort(key=lambda t: t[0].stat().st_mtime, reverse=True)
        out = []
        for d, app_label in found:
            meta: dict = {}
            mf = d / "meta.json"
            if mf.exists():
                try: meta = json.loads(mf.read_text(encoding="utf-8"))
                except Exception: pass
            out.append((d, meta, app_label))
        return out

    def _refresh(self):
        for iid in self._tree.get_children(): self._tree.delete(iid)
        filt = getattr(self, "_filter_var", None)
        filt_text = filt.get() if filt is not None else ""
        for d, _, app in self._scan_dirs():
            _fill_tree_row(self._tree, d, app=app, filter_text=filt_text)

    def _sel(self):
        return _tree_selected_dir(self._tree)

    def _open_selected(self):
        _open_selected_report_folder(self._app, self._tree)

    def _open_html(self):
        d = self._sel()
        if not d: return
        html = _find_report_html(d)
        if html: _open_path(html)
        else: self._app._show_warn_popup("Open HTML", f"No HTML report in:\n{d}")

    def _export_csv(self):
        d = self._sel()
        if not d: return
        # New naming is '<service>+<user>_<date>.csv' (+ matching .zip bundle);
        # fall back to the legacy 'findings.csv'. Prefer the richer .zip bundle.
        src = next(iter(sorted(d.glob("*.zip"))), None) \
            or (d / "findings.csv" if (d / "findings.csv").exists() else None) \
            or next(iter(sorted(d.glob("*.csv"))), None)
        if not src or not src.exists():
            self._app._show_warn_popup("Export CSV", f"No CSV/ZIP export in:\n{d}"); return
        ext = src.suffix
        path = filedialog.asksaveasfilename(title="Export CSV", defaultextension=ext,
            initialdir=str(d), initialfile=src.name,
            filetypes=[("ZIP bundle", "*.zip"), ("CSV", "*.csv"), ("All", "*.*")])
        if not path: return
        shutil.copyfile(src, path)
        self._app._show_info_popup("Export CSV", f"Wrote {path}")

    def _export_sarif(self):
        d = self._sel()
        if not d: return
        if not any((d / n).exists() for n in ("snyk_test.json", "snyk_code.json", "dast.json", "api.json")):
            self._app._show_warn_popup("Export SARIF", f"No raw scan output in:\n{d}"); return
        try:
            sarif = export_sarif(d); export_merged_json(d)
        except Exception as e:
            self._app._show_error_popup("Export SARIF", f"Failed:\n{e}"); return
        if not sarif:
            self._app._show_warn_popup("Export SARIF", "Nothing to export — no findings were assembled."); return
        path = filedialog.asksaveasfilename(title="Export SARIF", defaultextension=".sarif",
            initialdir=str(d), initialfile="findings.sarif", filetypes=[("SARIF", "*.sarif *.json"), ("All", "*.*")])
        if not path:
            self._app._show_info_popup("Export SARIF", f"SARIF written in report folder:\n{sarif}"); return
        try:
            shutil.copyfile(sarif, path)
        except Exception as e:
            self._app._show_error_popup("Export SARIF", f"Could not copy:\n{e}"); return
        self._app._show_info_popup("Export SARIF", f"Wrote {path}")

    def _delete(self):
        _delete_selected_report(self._app, self._tree, self._refresh)


# ── Tab mixins ──────────────────────────────────────────────────────────────
# Each gui_*_tab.py is logically part of *this* module — split out only so
# "I need to fix something on the DAST tab" means opening a ~950-line file
# instead of scrolling through one ~4500-line one. They use bare module-level
# names the same way the rest of this file does (T["accent"], run_dast(...),
# _make_tree(...), etc.) rather than self.something, so importing them here
# at the top would leave those names unresolved inside a *different* module's
# globals(). _wire_mixin_globals() (called once, after _load_runtime() has
# finished injecting the engine functions) mirrors this module's globals into
# each mixin module's own namespace — the same trick _load_runtime() already
# uses for static_scanner/dast_api/report_engine. T is mutated in place
# (T.update(...), never reassigned — see _apply_palette), so a mirrored
# reference to it stays correct across theme toggles.
import gui_scan_tab, gui_dast_tab, gui_api_tab, gui_static_tab, gui_reports_tab, gui_apps_tab
from gui_scan_tab import _ScanTabMixin
from gui_dast_tab import _DastTabMixin
from gui_api_tab import _ApiTabMixin
from gui_static_tab import _StaticTabMixin
from gui_reports_tab import _ReportsTabMixin
from gui_apps_tab import _AppsTabMixin

_MIXIN_MODULES = (gui_scan_tab, gui_dast_tab, gui_api_tab,
                  gui_static_tab, gui_reports_tab, gui_apps_tab)


def _wire_mixin_globals() -> None:
    shared = globals()
    for mod in _MIXIN_MODULES:
        for k, v in shared.items():
            if not k.startswith("__"):
                mod.__dict__[k] = v


class ScannerApp(_ScanTabMixin, _DastTabMixin, _ApiTabMixin, _StaticTabMixin,
                 _ReportsTabMixin, _AppsTabMixin, tk.Tk):
    """SecDevOps Banco Base — Integrated.py look & feel.

    The tab-specific logic (build + handlers for Scan/DAST/API/Static/Reports/
    Apps) lives in the 6 mixins above, each in its own gui_*_tab.py file —
    this class itself only keeps the shared infrastructure that every tab
    depends on: settings/session persistence, theming, the generic popup/
    widget helpers, the status bar, and the async-job runner. See
    _wire_mixin_globals() near the top of this file for how the mixins get
    access to this module's globals (T, fonts, the runtime-injected engine
    functions) without a circular import."""


    def __init__(self, boot_warnings: Optional[list[tuple[str, str]]] = None):
        super().__init__()
        self.title(APP_BRAND_NAME)
        self.configure(bg=T["bg"])
        self._user = _detect_user()
        self._boot_warnings = boot_warnings or []
        try: self.protocol("WM_DELETE_WINDOW", self._on_app_close)
        except Exception: pass
        try:
            if IS_WIN:
                self.state("zoomed")
            elif IS_MAC:
                sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
                self.geometry(f"{sw}x{sh}+0+0")
                try: self.state("zoomed")
                except Exception: pass
            else:
                self.attributes("-zoomed", True)
        except Exception:
            self.geometry("1400x900")

        self.fonts = {
            "title": (_FUI, 28, "bold"), "heading": (_FUI, 18, "bold"),
            "sub": (_FUI, 13, "bold"), "body": (_FUI, 12), "small": (_FUI, 11),
            "caption": (_FUI, 10), "mono": (_FMONO, 11), "tab": (_FUI, 11, "bold"),
            "emoji": (_FUI, 14),
        }
        self._event_queue: queue.Queue = queue.Queue()
        self._auth_proc: Optional[subprocess.Popen] = None
        self._auth_deadline = 0.0
        self._target = DEFAULT_TARGET
        self._reports_root = DEFAULT_REPORTS
        self._last_report: Optional[Path] = None
        self._last_context: Optional[dict] = None
        self._last_report_dir: Optional[Path] = None
        self._last_static_report: Optional[Path] = None
        self._static_busy = False
        self._checks: dict[str, CheckResult] = {}
        self._busy = False
        self._cancel_evt = threading.Event()
        self._static_cancel_evt = threading.Event()
        self._console_visible = False
        self._unread_log = 0
        self._active_tab: str = "scan"
        self._inv_tab: Optional[Any] = None
        self._active_app: Optional[dict] = None
        self._last_app_id: Optional[str] = None
        self._dark_mode = False
        self._auto_open = True
        self._max_log_lines = 2000
        self._load_settings()

        from app_inventory import AppInventoryStore
        self._inv_store = AppInventoryStore(self._reports_root)
        from report_engine import ScanStateStore
        self._scan_state = ScanStateStore(self._reports_root)

        self._setup_styles()
        self._build_vars()
        self._build_ui()
        if self._boot_warnings:
            self._log_line(f"[boot] ⚠ {len(self._boot_warnings)} optional component(s) had install "
                            "problems — the corresponding scan stage may not be available:")
            for label, detail in self._boot_warnings:
                self._log_line(f"[boot]   • {label}: {detail}")
            self._log_line("[boot]   Full detail in boot_dependencies.log next to the program.")
        self.after(150, self._drain_events)
        self.after(200, self._auto_load_last_app)
        self.after(300, lambda: self._run_async(self._recheck, label="initial env check"))
        # Resolve the webdriver in the background so the first macro recording
        # opens its browser instantly instead of stalling on Selenium Manager.
        self.after(1200, lambda: threading.Thread(
            target=lambda: prewarm_driver(self._collect_dast_cfg(), self._emit_log)
            if _RUNTIME_READY else None, daemon=True).start())
        # If a scan was in flight when the program last closed, offer to resume.
        self.after(700, self._check_unclean_shutdown)

    # Settings persistence
    def _load_settings(self):
        if not SETTINGS_FILE.exists(): return
        try: data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except Exception: return
        if "dark_mode" in data:
            self._dark_mode = bool(data["dark_mode"]); _apply_palette(self._dark_mode)
        if data.get("reports_root"): self._reports_root = Path(data["reports_root"])
        if "auto_open"     in data: self._auto_open     = bool(data["auto_open"])
        if data.get("last_app_id"): self._last_app_id   = str(data["last_app_id"])
        stages = data.get("scan_stages")
        if isinstance(stages, dict):
            self._saved_scan_stages = {k: bool(v) for k, v in stages.items()
                                       if k in ("sca", "code", "dast", "api", "secrets")}
        paths = data.get("static_paths")
        if isinstance(paths, list):
            self._saved_static_paths = [str(p) for p in paths if isinstance(p, str) and p.strip()]
        # Cache DAST/API field data — applied in _restore_dast/api_fields()
        # which run from _build_vars() once the tk.Vars exist.
        if isinstance(data.get("dast_fields"), dict):
            self._saved_dast_fields = data["dast_fields"]
        if isinstance(data.get("api_fields"), dict):
            self._saved_api_fields = data["api_fields"]

    def _save_settings(self):
        data = {"dark_mode": self._dark_mode, "reports_root": str(self._reports_root),
                "auto_open": self._auto_open,
                "last_app_id": getattr(self, "_last_app_id", None)}
        sv = getattr(self, "_scan_vars", None)
        if sv and not getattr(self, "_active_app", None):
            try:
                data["scan_stages"] = {k: bool(v.get()) for k, v in sv.items()}
            except Exception:
                pass
        lb = getattr(self, "_static_paths_lb", None)
        if lb is not None and not getattr(self, "_active_app", None):
            try:
                data["static_paths"] = [p for p in lb.get(0, "end")
                                        if p.strip() and not p.strip().startswith("(empty")]
            except Exception:
                pass
        # ── DAST fields (non-secret) ───────────────────────────────────────────
        try:
            _SECRET = {"password", "token", "cookie", "header_value",
                       "selenium_pass_value", "login_data"}
            data["dast_fields"] = {
                "url":      self._dast_url_var.get(),
                "auth":     self._dast_auth_var.get(),
                "profile":  self._dast_profile_var.get(),
                "pages":    int(self._dast_pages_var.get() or 30),
                "subs":     bool(self._dast_subs_var.get()),
                "tls":      bool(self._dast_tls_var.get()),
                "relogin":  bool(self._dast_relogin_var.get()),
                "exclude":  self._dast_exclude_var.get(),
                "rps":      float(self._dast_rps_var.get() or 8.0),
                "workers":  int(self._dast_workers_var.get() or 4),
                "proxy":    self._dast_proxy_var.get(),
                "browser":  self._dast_browser_var.get(),
                "headless": bool(self._dast_headless_var.get()),
                "selwait":  int(self._dast_selwait_var.get() or 15),
                "creds":    {k: v.get() for k, v in self._dast_cred_vars.items()
                             if k not in _SECRET},
            }
        except Exception:
            pass
        # ── API fields (non-secret) ────────────────────────────────────────────
        try:
            data["api_fields"] = {
                "spec":    self._api_spec_var.get(),
                "base":    self._api_base_var.get(),
                "auth":    self._api_auth_var.get(),
                "profile": self._api_profile_var.get(),
                "pages":   int(self._api_pages_var.get() or 80),
                "tls":     bool(self._api_tls_var.get()),
                "rps":     float(self._api_rps_var.get() or 8.0),
                "workers": int(self._api_workers_var.get() or 6),
                "proxy":   self._api_proxy_var.get(),
                "exclude": self._api_exclude_var.get(),
                "creds":   {k: v.get() for k, v in self._api_cred_vars.items()
                            if k not in _SECRET},
            }
        except Exception:
            pass
        try: SETTINGS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e: self._emit_log(f"[settings] could not save: {e}")

    def _persist_to_app_or_settings(self, app_field: str, value, *, log_label: str) -> None:
        """Shared 'where does this field live' rule used by every per-tab
        persist method: if an app profile is active, the field belongs to
        that app's record (so switching apps swaps the value in); otherwise
        it belongs to the global settings file. Was previously duplicated
        almost verbatim across _persist_static_paths / _persist_scan_stages —
        this is the one place that pattern lives now."""
        active_app = getattr(self, "_active_app", None)
        if active_app is not None:
            active_app[app_field] = value
            try:
                self._inv_store.save_app(active_app)
            except Exception as e:
                self._emit_log(f"[apps] could not save {log_label} to app profile: {e!r}")
        else:
            self._save_settings()

    def _persist_static_paths(self) -> None:
        """Save the current static-analysis path list to wherever it belongs:
        the active app's own profile record if one is loaded (so switching
        apps swaps in the right list), otherwise the global settings file."""
        lb = getattr(self, "_static_paths_lb", None)
        paths = [p for p in (lb.get(0, "end") if lb is not None else [])
                if p.strip() and not p.strip().startswith("(empty")]
        self._persist_to_app_or_settings("static_paths", paths, log_label="static_paths")

    def _persist_scan_stages(self) -> None:
        """Save the pipeline stage selection (SCA/SAST/DAST/API/Secrets
        toggles) to wherever it belongs — same per-app-first pattern as
        _persist_static_paths. app_inventory stores this as a list of the
        keys that are ON (matching AppProfileEditor's own format), not the
        {key: bool} dict the global settings file uses."""
        sv = getattr(self, "_scan_vars", None)
        selected = [k for k, v in (sv or {}).items() if v.get()]
        self._persist_to_app_or_settings("scan_stages", selected, log_label="scan_stages")

    # ── Crash / mid-scan recovery ─────────────────────────────────────────────
    # A small marker file records the in-flight scan's *non-secret* config. It's
    # written when a scan begins and removed on clean completion. If it's still
    # there next launch, the program was closed or crashed mid-scan.
    def _session_snapshot(self, kind: str, selected: set) -> dict:
        sel = sorted(selected)
        # DAST / API auth that isn't "none" needs a secret we deliberately never
        # persist (passwords/tokens/cookies live in memory only).
        needs_pw = (("dast" in sel and self._dast_auth_var.get() != "none") or
                    ("api"  in sel and self._api_auth_var.get()  != "none"))
        try:
            static_paths = [p for p in (getattr(self, "_static_paths_lb", None) and
                            self._static_paths_lb.get(0, "end") or [])
                            if p.strip() and not p.strip().startswith("(empty")]
        except Exception:
            static_paths = []
        # Non-secret DAST fields worth restoring (passwords/tokens excluded).
        _SECRET = {"password", "token", "cookie", "header_value",
                   "selenium_pass_value", "login_data"}
        dast_creds = {k: v.get() for k, v in self._dast_cred_vars.items()
                      if k not in _SECRET}
        dast = {
            "url": self._dast_url_var.get(), "auth": self._dast_auth_var.get(),
            "profile": self._dast_profile_var.get(), "pages": int(self._dast_pages_var.get() or 30),
            "subs": bool(self._dast_subs_var.get()), "tls": bool(self._dast_tls_var.get()),
            "relogin": bool(self._dast_relogin_var.get()), "exclude": self._dast_exclude_var.get(),
            "rps": float(self._dast_rps_var.get() or 8.0), "workers": int(self._dast_workers_var.get() or 4),
            "proxy": self._dast_proxy_var.get(), "browser": self._dast_browser_var.get(),
            "headless": bool(self._dast_headless_var.get()), "selwait": int(self._dast_selwait_var.get() or 15),
            "creds": dast_creds,
        }
        api_creds = {k: v.get() for k, v in self._api_cred_vars.items() if k not in _SECRET}
        api = {
            "spec": self._api_spec_var.get(), "base": self._api_base_var.get(),
            "auth": self._api_auth_var.get(), "profile": self._api_profile_var.get(),
            "pages": int(self._api_pages_var.get() or 80), "tls": bool(self._api_tls_var.get()),
            "rps": float(self._api_rps_var.get() or 8.0), "workers": int(self._api_workers_var.get() or 6),
            "proxy": self._api_proxy_var.get(), "exclude": self._api_exclude_var.get(),
            "creds": api_creds,
        }
        return {
            "kind": kind, "selected": sel, "needs_password": needs_pw,
            "target": self._target_var.get(), "reports_root": self._reports_var.get(),
            "static_paths": static_paths, "dast": dast, "api": api,
            "app_id": getattr(self, "_last_app_id", None),
            "started": _ts(),
        }

    def _session_begin(self, kind: str, selected: set):
        """Crash-recovery marker, keyed by lane ('pipeline' / 'static') so the
        two independent run lanes don't clobber each other's marker if both
        happen to be in flight when the app is killed."""
        try:
            sessions = self._read_session_file()
            sessions[kind] = self._session_snapshot(kind, selected)
            SESSION_FILE.write_text(json.dumps({"sessions": sessions}, indent=2), encoding="utf-8")
        except Exception as e:
            self._emit_log(f"[session] could not write marker: {e!r}")

    @staticmethod
    def _read_session_file() -> dict:
        """Returns {lane: snapshot}. Tolerates the old single-record format
        (a flat dict with 'kind' at the top level, from before lanes existed)
        by treating it as one entry under its own 'kind'."""
        if not SESSION_FILE.exists():
            return {}
        try:
            raw = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
        if isinstance(raw, dict) and "sessions" in raw and isinstance(raw["sessions"], dict):
            return raw["sessions"]
        if isinstance(raw, dict) and "kind" in raw:
            return {raw["kind"]: raw}
        return {}

    def _session_end(self, kind: Optional[str] = None):
        """Clear one lane's marker. If that was the last remaining lane (or
        no kind is given), remove the file entirely."""
        try:
            if not SESSION_FILE.exists():
                return
            if kind is None:
                SESSION_FILE.unlink(missing_ok=True)
                return
            sessions = self._read_session_file()
            sessions.pop(kind, None)
            if sessions:
                SESSION_FILE.write_text(json.dumps({"sessions": sessions}, indent=2), encoding="utf-8")
            else:
                SESSION_FILE.unlink(missing_ok=True)
        except Exception:
            try:
                if SESSION_FILE.exists(): SESSION_FILE.unlink()
            except Exception: pass

    def _check_unclean_shutdown(self):
        sessions = self._read_session_file()
        if not sessions:
            return
        # The marker is consumed now so we never prompt twice for the same crash.
        try: SESSION_FILE.unlink(missing_ok=True)
        except Exception: pass
        # Rare in practice (both lanes mid-flight at the same crash) — prompt
        # once per leftover lane rather than trying to merge them into one
        # popup, since each resumes independently.
        for kind, info in sessions.items():
            self._prompt_resume_session(kind, info)

    def _prompt_resume_session(self, kind: str, info: dict):
        sel = info.get("selected") or []
        modes = " + ".join(s.upper() for s in sel) or "—"
        needs_pw = bool(info.get("needs_password"))
        started = info.get("started", "")
        lane_label = "static analysis" if kind == "static" else "full pipeline"
        pw_note = ""
        if needs_pw:
            which = []
            if "dast" in sel and (info.get("dast") or {}).get("auth", "none") != "none": which.append("DAST")
            if "api"  in sel and (info.get("api")  or {}).get("auth", "none") != "none": which.append("API")
            pw_note = (f"\n\nNote: that scan included {' and '.join(which)}, which uses "
                       "credentials. Passwords/tokens are never saved to disk, so you'll "
                       "need to re-enter them before running. Everything else will be restored.")
        msg = (f"The program closed unexpectedly while a {lane_label} scan was running.\n\n"
               f"Last scan configuration:\n"
               f"   •  Stages:  {modes}\n"
               f"   •  Target:  {info.get('target','—')}\n"
               f"   •  Started: {started}\n\n"
               "Do you want to run that scan again with the same configuration?" + pw_note)
        self._show_confirm_popup(
            "Unexpected shutdown", msg,
            on_yes=lambda: self._resume_from_session(info),
            yes_label="  ▶  Yes, restore and run  " if not needs_pw else "  ↩  Restore config  ",
            no_label="  No, start clean  ")

    def _resume_from_session(self, info: dict):
        sel = set(info.get("selected") or [])
        # Restore stage selection + repaint the cards.
        for k in ("sca", "code", "dast", "api", "secrets"):
            var = self._scan_vars.get(k)
            if var is not None: var.set(1 if k in sel else 0)
            fn = getattr(self, "_stage_apply", {}).get(k)
            if fn:
                try: fn(k in sel)
                except Exception as e:
                    self._emit_log(f"[session] stage card restore failed for '{k}': {e!r}")
        if info.get("target"): self._target_var.set(info["target"])
        if info.get("reports_root"): self._reports_var.set(info["reports_root"])
        # Restore static path list.
        try:
            if hasattr(self, "_static_paths_lb"):
                self._static_paths_lb.delete(0, "end")
                for p in info.get("static_paths", []):
                    self._static_paths_lb.insert("end", p)
        except Exception as e:
            self._emit_log(f"[session] static path list restore failed: {e!r}")
        # Restore non-secret DAST config.
        d = info.get("dast") or {}
        try:
            self._dast_url_var.set(d.get("url", "https://")); self._dast_auth_var.set(d.get("auth", "auto"))
            self._dast_profile_var.set(d.get("profile", "passive")); self._dast_pages_var.set(int(d.get("pages", 30)))
            self._dast_subs_var.set(bool(d.get("subs", False))); self._dast_tls_var.set(bool(d.get("tls", True)))
            self._dast_relogin_var.set(bool(d.get("relogin", True)))
            if d.get("exclude") is not None: self._dast_exclude_var.set(d["exclude"])
            self._dast_rps_var.set(float(d.get("rps", 8.0))); self._dast_workers_var.set(int(d.get("workers", 4)))
            self._dast_proxy_var.set(d.get("proxy", "")); self._dast_browser_var.set(d.get("browser", "chrome"))
            self._dast_headless_var.set(bool(d.get("headless", True))); self._dast_selwait_var.set(int(d.get("selwait", 15)))
            for k, v in (d.get("creds") or {}).items():
                if k in self._dast_cred_vars: self._dast_cred_vars[k].set(v)
        except Exception as e:
            self._emit_log(f"[session] DAST restore partial: {e!r}")
        # Restore non-secret API config.
        a = info.get("api") or {}
        try:
            self._api_spec_var.set(a.get("spec", "")); self._api_base_var.set(a.get("base", ""))
            self._api_auth_var.set(a.get("auth", "none")); self._api_profile_var.set(a.get("profile", "passive"))
            self._api_pages_var.set(int(a.get("pages", 80))); self._api_tls_var.set(bool(a.get("tls", True)))
            self._api_rps_var.set(float(a.get("rps", 8.0))); self._api_workers_var.set(int(a.get("workers", 6)))
            self._api_proxy_var.set(a.get("proxy", ""))
            if a.get("exclude") is not None: self._api_exclude_var.set(a["exclude"])
            for k, v in (a.get("creds") or {}).items():
                if k in self._api_cred_vars: self._api_cred_vars[k].set(v)
        except Exception as e:
            self._emit_log(f"[session] API restore partial: {e!r}")
        try: self._refresh_scan_btn()
        except Exception: pass
        try: self._save_settings()
        except Exception: pass

        if info.get("needs_password"):
            # We can't auto-run: the credentials weren't persisted. Send the user
            # to the right tab to re-enter them, then run.
            tab = "dast" if ("dast" in sel and (info.get("dast") or {}).get("auth","none") != "none") else "api"
            try: self._show_tab(tab)
            except Exception: pass
            try:
                if tab == "dast": self._refresh_dast_creds()
            except Exception: pass
            self._show_info_popup(
                "Restored — password needed",
                "I restored the previous scan's configuration.\n\n"
                f"Since it includes {tab.upper()} with authentication, re-enter "
                "the password/token in the credentials fields, then press "
                "▶ Run to start the scan.")
            return

        # No secrets needed → resume automatically. The initial "env check"
        # kicked off at startup (self.after(300, ...)) runs in the background
        # and holds self._busy for as long as it takes the Snyk CLI to answer.
        # If we call _start_scan()/_start_static_scan() while that's still in
        # flight, _run_async() silently no-ops (busy guard) and the scan never
        # actually runs — which is exactly what looked like "passes the env
        # check but never auto-runs". Wait for it to clear first, with a hard
        # cap so we never hang here forever even if it never clears.
        self._emit_log("[session] resuming previous scan with restored config…")
        kind = info.get("kind")
        attempts = [0]
        def _kick_off():
            if getattr(self, "_busy", False) and attempts[0] < 75:  # ~15s cap (75 * 200ms)
                attempts[0] += 1
                self.after(200, _kick_off)
                return
            if getattr(self, "_busy", False):
                self._emit_log("[session] still busy after 15s wait — forcing resume anyway "
                               "(the scan may queue behind whatever is running).")
            if kind == "static":
                self._show_tab("static")
                self._start_static_scan({s for s in sel if s in ("sca", "code", "secrets")} or
                                        {"sca", "code", "secrets"})
            else:
                self._show_tab("scan")
                self._start_scan()
        _kick_off()

    def _show_confirm_popup(self, title, message, *, on_yes,
                            yes_label="  Yes  ", no_label="  No  "):
        popup = self._create_popup(title)
        self._popup_hdr(popup, title, icon="⚠")
        self._centered_msg(popup, "⚠", T["accent"], title, message, T["text"])
        def _yes():
            popup.close()
            try: on_yes()
            except Exception as e: self._emit_log(f"[session] resume failed: {e!r}")
        self._popup_foot(popup, (no_label, popup.close, "flat"), (yes_label, _yes, "accent"))

    # Theme
    def _apply_theme_to_app(self):
        _apply_palette(self._dark_mode)
        self._setup_styles()
        self._recolour_widget(self)
        self._recolour_ribbon_tabs()
        # Re-paint pipeline stage cards — _apply_state now reads T[] live, but
        # we must call it so deselected cards move from the old surface2 to the
        # new one.  Also refreshes idle pill colours.
        try: self._refresh_stage_cards()
        except Exception: pass
        # Any remaining idle pills not reached by _refresh_stage_cards
        for key, pill in getattr(self, "_stage_pills", {}).items():
            try:
                if pill.cget("text") == "● IDLE":
                    pill.configure(bg=T["pill_idle_bg"], fg=T["pill_idle_fg"])
            except Exception: pass
        for _attr in ("_static_sca_tree", "_static_sast_tree"):
            _t = getattr(self, _attr, None)
            if _t is not None:
                try: self._apply_group_tags(_t)   # ttk tree tags aren't caught by _recolour_widget
                except Exception: pass
        inv_tab = getattr(self, "_inv_tab", None)
        if inv_tab:
            try: inv_tab.apply_theme()
            except Exception:
                try: inv_tab.refresh()
                except Exception: pass

    def _recolour_widget(self, w):
        cls = w.__class__.__name__
        try:
            if cls in ("Frame", "Canvas"):
                role = _ROLE_BG.get(w.cget("bg"))
                if role: w.configure(bg=T[role])
                if cls == "Frame":
                    try:
                        if w.cget("highlightbackground") in _BORDERS:
                            w.configure(highlightbackground=T["border"])
                    except Exception: pass
            elif cls == "Label":
                new_fg = _ROLE_ACCENT.get(w.cget("fg")) or _ROLE_FG.get(w.cget("fg"))
                new_bg = _ROLE_ACCENT.get(w.cget("bg")) or _ROLE_BG.get(w.cget("bg"))
                if new_fg: w.configure(fg=T[new_fg])
                if new_bg: w.configure(bg=T[new_bg])
            elif cls == "Button":
                acc = _ROLE_ACCENT.get(w.cget("bg"))
                if acc:
                    w.configure(bg=T[acc], activebackground=T[acc + "_hi"])
                else:
                    role = _ROLE_BTN_BG.get(w.cget("bg"))
                    if role: w.configure(bg=T[role], activebackground=T["card_hover"])
                new_fg = _ROLE_ACCENT.get(w.cget("fg")) or _ROLE_FG.get(w.cget("fg"))
                if new_fg: w.configure(fg=T[new_fg])
            elif cls == "Radiobutton":
                bg_role = _ROLE_BG.get(w.cget("bg"))
                if bg_role: w.configure(bg=T[bg_role])
                fg_role = _ROLE_FG.get(w.cget("fg"))
                if fg_role: w.configure(fg=T[fg_role])
                w.configure(activebackground=T["card_hover"], selectcolor=T["surface2"])
            elif cls == "Checkbutton":
                bg_role = _ROLE_BG.get(w.cget("bg"))
                if bg_role: w.configure(bg=T[bg_role], activebackground=T["card_hover"])
                fg_role = _ROLE_FG.get(w.cget("fg"))
                if fg_role: w.configure(fg=T[fg_role])
            elif cls == "Text":
                w.configure(bg=T["surface2"], fg=T["text"], insertbackground=T["text"])
            elif cls == "Listbox":
                w.configure(bg=T["surface2"], fg=T["text"],
                            selectbackground=T["accent"], selectforeground=T["button_fg"])
        except Exception: pass
        for child in w.winfo_children():
            self._recolour_widget(child)

    def _recolour_ribbon_tabs(self):
        active = getattr(self, "_active_tab", "scan")
        for k, btn in getattr(self, "_ribbon_tabs", {}).items():
            try:
                if k == active:
                    btn.config(bg=T["accent"], fg=T["button_fg"])
                else:
                    btn.config(bg=T["panel_bg"], fg=T["text"],
                               activebackground=T["card_hover"], activeforeground=T["accent"])
            except Exception: pass
        run_wrap = getattr(self, "_run_icon_wrap", None)
        if run_wrap:
            try:
                run_wrap.configure(bg=T["accent"])
                run_btn = getattr(self, "_run_icon_btn", None)
                if run_btn: run_btn.configure(fg=T["accent"])
            except Exception: pass
        self._update_stop_btn_style()

    def _setup_styles(self):
        s = ttk.Style(self)
        try: s.theme_use("clam")
        except tk.TclError: pass
        f = (_FUI, 12)
        s.configure(".", background=T["bg"], foreground=T["text"], font=f)
        for name, bg in [("TFrame", T["bg"]), ("Card.TFrame", T["panel_bg"]), ("Surface.TFrame", T["panel_bg"])]:
            s.configure(name, background=bg)
        for name, bg, fg in [
            ("TLabel", T["bg"], T["text"]), ("Surface.TLabel", T["panel_bg"], T["text"]),
            ("Muted.TLabel", T["bg"], T["muted"]), ("MutedS.TLabel", T["panel_bg"], T["muted"]),
            ("Section.TLabel", T["panel_bg"], T["muted"])]:
            s.configure(name, background=bg, foreground=fg)
        s.configure("Section.TLabel", font=(_FUI, 10, "bold"))
        s.configure("TButton", background=T["surface2"], foreground=T["text"],
                    bordercolor=T["border"], padding=(10, 6), relief="flat")
        s.map("TButton", background=[("active", T["card_hover"]), ("disabled", T["surface2"])],
              foreground=[("disabled", T["muted"])])
        for name, bg, bga in [("Accent.TButton", T["accent"], T["accent_hi"]),
                              ("Danger.TButton", T["accent2"], T["accent2_hi"])]:
            s.configure(name, background=bg, foreground=T["button_fg"], font=(_FUI, 11, "bold"), padding=(14, 8))
            s.map(name, background=[("active", bga), ("disabled", T["surface2"])], foreground=[("disabled", T["muted"])])
        s.configure("Ghost.TButton", background=T["panel_bg"], foreground=T["text"],
                    bordercolor=T["border"], relief="solid", borderwidth=1, padding=(8, 5))
        s.map("Ghost.TButton", background=[("active", T["surface2"]), ("disabled", T["panel_bg"])],
              foreground=[("disabled", T["muted"])])
        s.configure("TEntry", fieldbackground=T["surface2"], foreground=T["text"], bordercolor=T["border"], padding=5)
        s.map("TEntry", bordercolor=[("focus", T["accent"])])
        s.configure("TCombobox", fieldbackground=T["surface2"], foreground=T["text"], arrowcolor=T["accent"])
        s.map("TCombobox", fieldbackground=[("readonly", T["surface2"])],
              selectbackground=[("readonly", T["accent"])], selectforeground=[("readonly", T["button_fg"])])
        # Style the Combobox dropdown popup (a native Tk Listbox).
        # option_add is the only cross-platform way to reach it.
        try:
            self.option_add("*TCombobox*Listbox.background",       T["surface2"])
            self.option_add("*TCombobox*Listbox.foreground",       T["text"])
            self.option_add("*TCombobox*Listbox.selectBackground", T["accent"])
            self.option_add("*TCombobox*Listbox.selectForeground", T["button_fg"])
        except Exception: pass
        s.configure("TCheckbutton", background=T["panel_bg"], foreground=T["text"])
        s.map("TCheckbutton", background=[("active", T["card_hover"])])
        s.configure("TSpinbox", fieldbackground=T["surface2"], foreground=T["text"])
        s.configure("Treeview", background=T["tree_bg"], foreground=T["text"], fieldbackground=T["tree_bg"],
                    rowheight=26, selectbackground=T["accent"], selectforeground=T["button_fg"])
        s.map("Treeview", background=[("selected", T["accent"])], foreground=[("selected", T["button_fg"])])
        s.configure("Treeview.Heading", background=T["tree_bg"], foreground=T["accent"],
                    font=(_FUI, 11, "bold"), relief="flat", borderwidth=0)
        s.map("Treeview.Heading", background=[("active", T["surface2"]), ("pressed", T["surface2"])],
              foreground=[("active", T["accent"])])
        s.configure("Vertical.TScrollbar", background=T["panel_bg"], troughcolor=T["bg"], bordercolor=T["border"])

    def _build_vars(self):
        self._target_var = tk.StringVar(value=str(self._target))
        self._reports_var = tk.StringVar(value=str(self._reports_root))
        _saved_stages = getattr(self, "_saved_scan_stages", None)
        def _stage_default(k):
            if _saved_stages is not None and k in _saved_stages:
                return _saved_stages[k]
            return k in ("sca", "code")   # first-run default
        self._scan_vars = {k: tk.BooleanVar(value=_stage_default(k))
                           for k in ("sca", "code", "dast", "api", "secrets")}
        self._dast_url_var = tk.StringVar(value="https://")
        self._dast_auth_var = tk.StringVar(value="auto")
        self._dast_profile_var = tk.StringVar(value="passive")
        self._dast_pages_var = tk.IntVar(value=30)
        self._dast_subs_var = tk.BooleanVar(value=False)
        self._dast_tls_var = tk.BooleanVar(value=True)
        self._dast_relogin_var = tk.BooleanVar(value=True)
        self._dast_exclude_var = tk.StringVar(value=(
            r"(?i)/(logout|log-?out|log-?off|signout|sign-?out|cerrar[-_]?sesion|"
            r"cerrarsesion|cerrar[-_]?session|salir|desconectar|desconexion|"
            r"deslog\w*|api/logout)\b"))
        self._dast_rps_var = tk.DoubleVar(value=8.0)
        self._dast_workers_var = tk.IntVar(value=4)
        self._dast_proxy_var = tk.StringVar(value="")
        self._dast_browser_var = tk.StringVar(value="chrome")
        self._dast_browser_label_var = tk.StringVar(value="Google Chrome")
        self._browser_catalog = {}
        self._browser_label_key = {}
        self._dast_headless_var = tk.BooleanVar(value=True)
        self._dast_selwait_var = tk.IntVar(value=15)
        self._dast_cred_vars = {k: tk.StringVar() for k in self._CRED_KEYS}
        self._api_spec_var = tk.StringVar(value="")
        self._api_base_var = tk.StringVar(value="")
        self._api_auth_var = tk.StringVar(value="none")
        self._api_profile_var = tk.StringVar(value="passive")
        self._api_pages_var = tk.IntVar(value=80)
        self._api_tls_var = tk.BooleanVar(value=True)
        self._api_rps_var = tk.DoubleVar(value=8.0)
        self._api_workers_var = tk.IntVar(value=6)
        self._api_proxy_var = tk.StringVar(value="")
        self._api_exclude_var = tk.StringVar(value=(
            r"(?i)/(logout|log-?out|log-?off|signout|sign-?out|cerrar[-_]?sesion|"
            r"cerrarsesion|cerrar[-_]?session|salir|desconectar|desconexion|"
            r"deslog\w*)\b"))
        self._api_cred_vars = {k: tk.StringVar() for k in
                               ("username", "password", "token", "cookie", "header_name", "header_value")}
        self._status_var = tk.StringVar(value='Initialising…')
        self._stage_pills: dict[str, tk.Label] = {}
        self._stage_apply: dict[str, Callable[[bool], None]] = {}
        self._stage_bar_update: dict[str, object] = {}
        self._pipe_stage_states: dict[str, str] = {}
        self._pipe_card_pcts: dict[str, float] = {}
        self._pipe_progress_pct: float = 0.0
        self._recent_paths: list[Path] = []
        # Restore persisted DAST/API field values now, before the UI is built,
        # so the correct values are already in the vars when the tabs render.
        self._restore_dast_fields()
        self._restore_api_fields()

    # Top-level UI
    def _build_ui(self):
        self._build_ribbon(); self._build_body(); self._build_status_bar(); self._show_tab("scan")

    def _build_ribbon(self):
        self._ribbon = tk.Frame(self, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        self._ribbon.pack(side="top", fill="x")
        tk.Frame(self._ribbon, bg=T["accent"], height=2).pack(fill="x", side="top")
        inner_row = tk.Frame(self._ribbon, bg=T["panel_bg"]); inner_row.pack(fill="x", side="top")
        self._ribbon_tabs: dict[str, tk.Button] = {}
        tabs = [("scan", "▶ Scan"), ("static", "🔍 Static"), ("dast", "🌐 DAST"), ("api", "🔌 API"),
                ("reports", "📋 Reports"), ("apps", "📦 Apps")]
        tab_area = tk.Frame(inner_row, bg=T["panel_bg"]); tab_area.pack(side="left", fill="y", padx=(10, 0))
        for key, label in tabs:
            btn = tk.Button(tab_area, text=label, command=lambda k=key: self._show_tab(k),
                            bg=T["panel_bg"], fg=T["text"], font=(_FUI, 10, "bold"), relief="flat", bd=0,
                            padx=10, pady=6, cursor="hand2", justify="center",
                            activebackground=T["card_hover"], activeforeground=T["accent"])
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=T["card_hover"])
                     if b != self._ribbon_tabs.get(self._active_tab) else None)
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg=T["panel_bg"])
                     if b != self._ribbon_tabs.get(self._active_tab) else None)
            btn.pack(side="left", fill="y", padx=1)
            self._ribbon_tabs[key] = btn
        right = tk.Frame(inner_row, bg=T["panel_bg"]); right.pack(side="right", padx=8)
        _run_wrap = tk.Frame(right, bg=T["accent"], padx=2, pady=2); _run_wrap.pack(side="left", padx=(0, 4))
        self._run_icon_btn = tk.Button(_run_wrap, text="▶", font=(_FUI, 14, "bold"), command=self._start_scan,
                                       bg=T["panel_bg"], fg=T["accent"], activebackground=T["surface2"],
                                       activeforeground=T["accent"], relief="flat", bd=0, padx=8, pady=4,
                                       cursor="hand2", disabledforeground=T["muted"], state="disabled")
        self._run_icon_btn.pack(fill="both", expand=True)
        self._run_icon_wrap = _run_wrap
        _stop_wrap = tk.Frame(right, bg=T["muted"], padx=2, pady=2); _stop_wrap.pack(side="left", padx=(0, 8))
        self._stop_icon_btn = tk.Button(_stop_wrap, text="■", font=(_FUI, 14, "bold"), command=self._request_cancel,
                                        bg=T["panel_bg"], fg=T["muted"], activebackground=T["surface2"],
                                        activeforeground=T["err"], relief="flat", bd=0, padx=8, pady=4,
                                        cursor="hand2", disabledforeground=T["muted"], state="disabled")
        self._stop_icon_btn.pack(fill="both", expand=True)
        self._stop_icon_wrap = _stop_wrap
        tk.Frame(self._ribbon, bg=T["border"], height=1).pack(fill="x", side="bottom")

    def _show_tab(self, key: str):
        self._active_tab = key
        for k, btn in self._ribbon_tabs.items():
            btn.config(bg=T["accent"], fg=T["button_fg"]) if k == key else btn.config(bg=T["panel_bg"], fg=T["text"])
        for k, frame in self._tab_frames.items():
            if k == key: frame.tkraise()

    def _build_body(self):
        body = tk.Frame(self, bg=T["bg"]); body.pack(side="top", fill="both", expand=True)
        self._console_frame = tk.Frame(body, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        self._build_console(self._console_frame)
        stack = tk.Frame(body, bg=T["bg"]); stack.pack(side="top", fill="both", expand=True)
        self._tab_frames: dict[str, tk.Frame] = {}
        builders = {"scan": self._build_tab_scan, "dast": self._build_tab_dast, "api": self._build_tab_api,
                    "static": self._build_tab_static, "reports": self._build_tab_reports,
                    "apps": self._build_tab_apps}
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
        # Granular progress: hidden until a stage reports real (n, total)
        # progress (DAST pages crawled, API endpoints tested). SCA/SAST stay
        # text-only in the status label — the Snyk CLI doesn't expose
        # sub-progress, so a fake bar there would just be decorative.
        self._progress_box = tk.Frame(bar, bg=T["panel_bg"])
        self._progress_lbl = tk.Label(self._progress_box, text="", font=self.fonts["caption"],
                                      bg=T["panel_bg"], fg=T["muted"])
        self._progress_lbl.pack(side="left", padx=(0, 6))
        self._progress_bar = ttk.Progressbar(self._progress_box, mode="determinate",
                                             length=140, maximum=100)
        self._progress_bar.pack(side="left")
        # not packed yet — _show_progress()/_hide_progress() control visibility
        tk.Label(bar, textvariable=self._status_var, font=self.fonts["caption"],
                 bg=T["panel_bg"], fg=T["accent"], anchor="center").pack(expand=True)

    def _show_progress(self, label: str, done: int, total: int) -> None:
        if not self._progress_box.winfo_ismapped():
            self._progress_box.pack(side="right", padx=(0, 12))
        pct = int(100 * done / total) if total else 0
        self._progress_bar["value"] = pct
        self._progress_lbl.config(text=f"{label}: {done}/{total}")

    def _hide_progress(self) -> None:
        if self._progress_box.winfo_ismapped():
            self._progress_box.pack_forget()


    def _toggle_theme(self):
        self._dark_mode = not self._dark_mode
        self._apply_theme_to_app(); self._save_settings()
        self._theme_btn.configure(text="🌙" if self._dark_mode else "☀")


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
            self._console_frame.pack(side="bottom", fill="x"); self._console_visible = True; self._unread_log = 0
        self._console_btn.configure(text="▥  Console", fg=T["text"])

    # Shared UI helpers
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

    def _safety_banner(self, parent, text: str) -> tk.Frame:
        """Persistent, can't-miss reminder shown at the top of tabs that fire
        real network traffic at whatever URL/spec is configured (DAST, API).
        Not a one-time popup — those get dismissed and forgotten; this stays
        on screen for as long as the tab is open."""
        f = tk.Frame(parent, bg=T["panel_bg"], highlightthickness=1,
                     highlightbackground=T["accent"], padx=12, pady=8)
        f.pack(fill="x", pady=(0, 10))
        tk.Label(f, text="⚠", font=(_FUI, 14, "bold"), bg=T["panel_bg"], fg=T["accent"]).pack(side="left")
        tk.Label(f, text=text, font=(_FUI, 10, "bold"), bg=T["panel_bg"], fg=T["text"],
                 anchor="w", justify="left", wraplength=760).pack(side="left", padx=(8, 0), fill="x", expand=True)
        return f

    # ── Static-analysis presentation (each area rendered to suit its data) ──────
    def _panel(self, parent, title, *, pady=(0, 10)):
        """Like _card but returns (inner_body, header_right) so callers can drop a
        live summary on the right of the gold header. Same brand chrome as _card."""
        outer = tk.Frame(parent, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        outer.pack(fill="x", pady=pady)
        hdr = tk.Frame(outer, bg=T["accent"], padx=14, pady=5); hdr.pack(fill="x")
        tk.Label(hdr, text=title, font=(_FUI, 10, "bold"), bg=T["accent"], fg=T["button_fg"], anchor="w").pack(side="left")
        right = tk.Frame(hdr, bg=T["accent"]); right.pack(side="right")
        inner = tk.Frame(outer, bg=T["panel_bg"], padx=14, pady=10); inner.pack(fill="both", expand=True)
        return inner, right


    def _side_card(self, row, title, *, padx=(0, 0), pad=14, ipady=10) -> tk.Frame:
        outer = tk.Frame(row, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        outer.pack(side="left", fill="both", expand=True, padx=padx)
        hdr = tk.Frame(outer, bg=T["accent"], padx=pad, pady=5); hdr.pack(fill="x")
        tk.Label(hdr, text=title, font=(_FUI, 10, "bold"), bg=T["accent"], fg=T["button_fg"], anchor="w").pack(side="left")
        inner = tk.Frame(outer, bg=T["panel_bg"], padx=pad, pady=ipady); inner.pack(fill="both", expand=True)
        return inner

    def _lbl(self, parent, text="", size=11, bold=False, bg=None, fg=None, **kw) -> tk.Label:
        return tk.Label(parent, text=text, font=(_FUI, size, "bold" if bold else "normal"),
                        bg=bg or T["panel_bg"], fg=fg or T["text"], **kw)

    def _btn(self, parent, text, cmd, kind="accent", **kw) -> tk.Button:
        _base_pad, _base_font = (12, 7), (_FUI, 11, "bold")
        p, is_in_ribbon = parent, False
        try:
            while p is not None:
                if getattr(self, "_ribbon", None) is p:
                    is_in_ribbon = True; break
                p = getattr(p, "master", None)
        except Exception:
            is_in_ribbon = False
        if is_in_ribbon:
            kinds = {
                "accent":  dict(bg=T["accent"], fg=T["button_fg"], activebackground=T["accent_hi"],
                                activeforeground=T["button_fg"], font=_base_font, padx=_base_pad[0], pady=_base_pad[1]),
                "danger":  dict(bg=T["accent2"], fg=T["button_fg"], activebackground=T["accent2_hi"],
                                activeforeground=T["button_fg"], font=_base_font, padx=_base_pad[0], pady=_base_pad[1]),
                "outline": dict(bg=T["panel_bg"], fg=T["accent"], activebackground=T["card_hover"],
                                activeforeground=T["accent_hi"], font=_base_font, padx=_base_pad[0],
                                pady=_base_pad[1], borderwidth=1, relief="solid"),
                "flat":    dict(bg=T["surface2"], fg=T["text"], activebackground=T["card_hover"],
                                activeforeground=T["accent"], font=(_FUI, 11), padx=10, pady=5),
            }
            cfg = kinds.get(kind, kinds["flat"])
        else:
            container = tk.Frame(parent, bg=T["accent"])
            inner_btn = tk.Button(container, text=text, command=cmd, bg=T["panel_bg"], fg=T["accent"],
                                  activebackground=T["card_hover"], activeforeground=T["accent_hi"],
                                  font=_base_font, padx=_base_pad[0], pady=_base_pad[1],
                                  cursor="hand2", bd=0, relief="flat", **kw)
            inner_btn.pack(fill="both", expand=True, padx=1, pady=1)
            inner_btn.pack = lambda *a, **kwa: container.pack(*a, **kwa)
            inner_btn.grid = lambda *a, **kwa: container.grid(*a, **kwa)
            inner_btn.container = container
            return inner_btn
        if "relief" not in cfg: cfg["relief"] = "flat"
        return tk.Button(parent, text=text, command=cmd, cursor="hand2", bd=0, **cfg, **kw)

    def _glabel(self, parent, text: str, row: int, col: int, tip: str = "") -> tk.Label:
        w = self._lbl(parent, text, size=10, fg=T["muted"], anchor="e")
        w.grid(row=row, column=col, sticky="e", padx=(0, 6), pady=3)
        if tip: return w

    def _spin(self, parent, label, var, frm, to, *, inc=None, width=6, padx=(0, 0)):
        if label:
            self._lbl(parent, label, size=10, fg=T["muted"]).pack(side="left", padx=(0, 4))
        kw = dict(from_=frm, to=to, textvariable=var, width=width)
        if inc is not None: kw["increment"] = inc
        sp = ttk.Spinbox(parent, **kw); sp.pack(side="left", padx=padx)
        return sp

    def _gentry(self, parent, var, row, col, tip="", *, span=1, **grid_kw):
        e = ttk.Entry(parent, textvariable=var)
        e.grid(row=row, column=col, columnspan=span, sticky="ew", pady=3, **grid_kw)
        if tip: return e

    def _hdiv(self, parent, **pk) -> tk.Frame:
        f = tk.Frame(parent, bg=T["border"], height=1); f.pack(fill="x", **pk)
        return f

    def _create_popup(self, title: str = "Window", w_pct: float = 0.75, h_pct: float = 0.75) -> tk.Frame:
        win = tk.Toplevel(self)
        win.title(title); win.configure(bg=T["bg"]); win.transient(self)
        _center_over(self, win, w_pct, h_pct)
        win.overrideredirect(True)
        win.update_idletasks(); win.lift(); win.focus_force()
        try: win.grab_set()
        except tk.TclError: pass
        _bind_ids: dict = {}

        def _close():
            try: win.grab_release()
            except Exception: pass
            for evt, bid in _bind_ids.items():
                try: self.unbind(evt, bid)
                except Exception: pass
            win.destroy()
            try: self.focus_force()
            except Exception: pass

        win.bind("<Escape>", lambda e: _close())
        _bind_ids.update(_popup_follow_parent(win, self))
        border = tk.Frame(win, bg=T["accent"], padx=2, pady=2); border.pack(fill="both", expand=True)
        content = tk.Frame(border, bg=T["bg"]); content.pack(fill="both", expand=True)
        content.close = _close   # type: ignore[attr-defined]
        content._win = win       # type: ignore[attr-defined]
        return content

    def _popup_hdr(self, popup: tk.Frame, title: str, subtitle: str = "", icon: str = "") -> tk.Frame:
        bg = T["panel_bg"]
        hdr = tk.Frame(popup, bg=bg, padx=30, pady=16); hdr.pack(fill="x")
        row = tk.Frame(hdr, bg=bg); row.pack(fill="x")
        tk.Label(row, text=f"{icon}  {title}" if icon else title, font=(_FUI, 15, "bold"),
                 bg=bg, fg=T["accent"]).pack(side="left")
        if subtitle:
            tk.Label(row, text=subtitle, font=(_FUI, 11, "italic"), bg=bg, fg=T["muted"]).pack(side="left", padx=(12, 0))
        _close_fn = getattr(popup, "close", None)
        if _close_fn:
            xbtn = tk.Label(row, text="✕", font=(_FUI, 13, "bold"), bg=bg, fg=T["muted"], cursor="hand2", padx=6)
            xbtn.pack(side="right")
            xbtn.bind("<Button-1>", lambda e: _close_fn())
            xbtn.bind("<Enter>", lambda e: xbtn.config(fg=T["err"]))
            xbtn.bind("<Leave>", lambda e: xbtn.config(fg=T["muted"]))
        self._hdiv(popup)
        return hdr

    def _popup_foot(self, popup: tk.Frame, *items, padx: int = 40, pady: int = 16, with_status: bool = False):
        bg = T["panel_bg"]
        self._hdiv(popup)
        bar = tk.Frame(popup, bg=bg, padx=padx, pady=pady); bar.pack(fill="x")
        status_lbl = None
        if with_status:
            status_lbl = tk.Label(bar, text="", font=(_FUI, 10), bg=bg, fg=T["muted"]); status_lbl.pack(side="left")
        for text, cmd, kind in items:
            self._btn(bar, text, cmd, kind).pack(side="right", padx=(6, 0))
        return (bar, status_lbl) if with_status else bar

    def _centered_msg(self, popup, icon, icon_color, title, message, msg_fg):
        """Shared centred icon + title + message body used by message/confirm popups."""
        bg = T["bg"]
        body = tk.Frame(popup, bg=bg); body.pack(fill="both", expand=True)
        tk.Frame(body, bg=bg).pack(fill="both", expand=True)
        row = tk.Frame(body, bg=bg); row.pack(padx=60)
        tk.Frame(body, bg=bg).pack(fill="both", expand=True)
        tk.Label(row, text=icon, font=(_FUI, 64), bg=bg, fg=icon_color).pack(side="left", padx=(0, 44))
        tk.Frame(row, bg=T["border"], width=1).pack(side="left", fill="y", padx=(0, 40))
        txt = tk.Frame(row, bg=bg); txt.pack(side="left", fill="x", expand=True)
        tk.Label(txt, text=title, font=(_FUI, 20, "bold"), bg=bg, fg=T["text"], anchor="w").pack(anchor="w")
        tk.Frame(txt, bg=T["border"], height=1).pack(fill="x", pady=(10, 12))
        tk.Label(txt, text=message, font=(_FUI, 13), bg=bg, fg=msg_fg, justify="left",
                 wraplength=1050, anchor="w").pack(anchor="w")

    def _choice_card(self, parent, icon, title, desc, *, enabled=True, icon_size=40, title_size=14,
                     desc_size=10, desc_wrap=None, ipadx=20, ipady=14, padx=12,
                     icon_pady=(18, 8), desc_pady=(6, 18)) -> tk.Frame:
        """Build one clickable choice card (icon/title/desc). Callers wire click & hover."""
        panel = T["panel_bg"]
        card = tk.Frame(parent, bg=panel, highlightthickness=2, highlightbackground=T["border"],
                        cursor="hand2" if enabled else "arrow")
        card.pack(side="left", padx=padx, ipadx=ipadx, ipady=ipady, fill="both", expand=True)
        tk.Label(card, text=icon, font=(_FUI, icon_size), bg=panel,
                 fg=T["accent"] if enabled else T["muted"]).pack(pady=icon_pady)
        tk.Label(card, text=title, font=(_FUI, title_size, "bold"), bg=panel,
                 fg=T["text"] if enabled else T["muted"]).pack()
        dkw = dict(justify="center")
        if desc_wrap: dkw["wraplength"] = desc_wrap
        tk.Label(card, text=desc, font=(_FUI, desc_size), bg=panel,
                 fg=T["muted"] if enabled else T["border"], **dkw).pack(pady=desc_pady)
        return card

    def _show_popup(self, title: str, message: str, kind: str = "info"):
        icon = {"info": "ℹ", "warn": "⚠", "error": "✕"}.get(kind, "ℹ")
        icon_color = {"info": T["accent"], "warn": T["accent"], "error": T["err"]}.get(kind, T["accent"])
        popup = self._create_popup(title)
        self._popup_hdr(popup, title, icon=icon)
        self._centered_msg(popup, icon, icon_color, title, message, T["err"] if kind == "error" else T["text"])
        self._popup_foot(popup, ("  OK  ", popup.close, "accent"))

    def _show_info_popup(self, title, message):  self._show_popup(title, message, "info")
    def _show_warn_popup(self, title, message):  self._show_popup(title, message, "warn")
    def _show_error_popup(self, title, message): self._show_popup(title, message, "error")


    # Tab: Scan


    def _on_app_close(self):
        """Save settings, wipe in-memory secrets, then kill the whole process group.
        The SESSION_FILE crash-recovery marker is left on disk intentionally so
        the next launch can offer to resume the interrupted scan."""
        try: self._save_settings()
        except Exception: pass
        try:
            for k in ("password", "token", "selenium_pass_value"):
                if k in self._dast_cred_vars: self._dast_cred_vars[k].set("")
            for k in ("password", "token"):
                if k in getattr(self, "_api_cred_vars", {}): self._api_cred_vars[k].set("")
        except Exception: pass
        try: self.destroy()
        except Exception: pass
        # Kill the entire process group so child processes (snyk CLI, Node,
        # Selenium drivers) don't keep running in the terminal after the window closes.
        try:
            if IS_WIN:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(os.getpid())],
                               capture_output=True)
            else:
                os.killpg(os.getpgid(os.getpid()), 9)
        except Exception:
            os._exit(0)


    # ── Auto-persistence for DAST and API fields ────────────────────────────────
    # Fields are saved automatically to .scanner_settings.json whenever they
    # change (replacing Save Profile / Load Profile buttons). Secrets (passwords,
    # tokens) are intentionally excluded from persistence — they remain
    # session-only and must be re-entered each run.


    def _run_async(self, fn: Callable[[], None], label: str = "",
                   *, busy_attr: str = "_busy", done_kind: str = "__done__"):
        """Runs `fn` on a background thread, gated by `busy_attr` instead of
        always the global `self._busy`. This is what lets the Static-tab
        quick scan (SCA/SAST/Secrets — no network dependency on a slow DAST
        crawl) run independently of the main pipeline (which already
        parallelizes its own selected stages internally via ThreadPoolExecutor
        — see _do_scan). Two different lanes, not unlimited concurrency: the
        crash-recovery session marker and Stop button still treat both lanes
        as 'a scan is running' so there's no ambiguity about what Stop does."""
        if getattr(self, busy_attr):
            self._log_line(f"[busy] ignoring '{label}' — another op in progress"); return
        setattr(self, busy_attr, True)
        self._update_stop_btn_style(); self._set_status(f"Running: {label}…")
        def wrap():
            try: fn()
            except Exception as e: self._log_line(f"[error] {e!r}")
            finally: self._event_queue.put((done_kind, label))
        threading.Thread(target=wrap, daemon=True).start()

    def _drain_events(self):
        try:
            while True:
                kind, payload = self._event_queue.get_nowait()
                if kind == "log":
                    self._log_line(payload)
                elif kind == "status":
                    self._set_status(payload)
                elif kind == "checks":
                    self._apply_checks(payload)
                elif kind == "auth_check_done":
                    self._auth_check_inflight = False
                    if payload is not None and getattr(payload, "ok", False):
                        self._log_line("[auth] authenticated.")
                        if self._auth_proc is not None:
                            _kill_process_tree(self._auth_proc)
                            self._auth_proc = None
                        # We already have a fresh CheckResult in `payload` (from the
                        # background thread in _kick_auth_check) — apply it directly
                        # instead of calling self._recheck(), which would shell out to
                        # `check_auth()` again synchronously on the UI thread. That's
                        # the exact anti-pattern _kick_auth_check's docstring warns
                        # about: it can block the whole window, sometimes for a long
                        # time, especially right after `snyk auth` exits and the two
                        # CLI calls contend for the same credentials-file lock.
                        self._apply_checks({"auth": payload})
                        # Auto-close the login popup if it is still open.
                        _close_fn = getattr(self, "_login_popup_close", None)
                        if callable(_close_fn):
                            _close_fn()
                elif kind == "stage":
                    key, label = payload
                    pill = self._stage_pills.get(key)
                    if pill:
                        style_map = {
                            "running": (T["pill_run_bg"], T["pill_run_fg"]),
                            "done":    (T["pill_ok_bg"],  T["pill_ok_fg"]),
                            "failed":  (T["pill_bad_bg"], T["pill_bad_fg"]),
                            "skipped": (T["pill_idle_bg"],T["pill_idle_fg"]),
                        }
                        bg, fg = style_map.get(label, (T["pill_idle_bg"], T["pill_idle_fg"]))
                        _pill_labels = {"running": "● RUN", "done": "● OK", "failed": "● FAIL", "skipped": "● SKIP"}
                        pill.config(text=_pill_labels.get(label, f"● {label.upper()[:4]}"), bg=bg, fg=fg)
                    # Actualizar barras de progreso por card y header PIPELINE
                    try:
                        self._update_pipeline_progress(key, label)
                    except Exception:
                        pass
                elif kind == "pipeline_reset":
                    # Resetear todas las barras al inicio de un nuevo scan
                    try:
                        self._pipe_stage_states = {}
                        self._pipe_card_pcts = {}
                        self._pipe_progress_pct = 0.0
                        cnv = self._pipe_hdr_canvas
                        cnv.coords("prog_rect", 0, 0, 0, 32)
                        _set_txt = getattr(self, "_pipe_hdr_set_prog_text", None)
                        if _set_txt:
                            _set_txt("⟳ iniciando…")
                        for bar_fn in getattr(self, "_stage_bar_update", {}).values():
                            bar_fn(0.0, T["border"])
                    except Exception:
                        pass
                elif kind == "progress":
                    label, done, total = payload
                    self._show_progress(label, done, total)
                    # Actualizar barra del card DAST/API/Secrets con progreso granular real
                    _prog_key_map = {"DAST": "dast", "API": "api", "Secrets": "secrets"}
                    _stage_key = _prog_key_map.get(label)
                    if _stage_key and total > 0:
                        _granular = done / total
                        try:
                            self._update_pipeline_progress(_stage_key, "running",
                                                           granular_pct=_granular)
                        except Exception:
                            pass
                elif kind == "auth_required":
                    self._prompt_relogin()
                elif kind == "report":
                    self._last_report = Path(payload)
                    self._open_btn.config(state="normal"); self._csv_btn.config(state="normal")
                    self._refresh_recent(); self._refresh_rep_tree()
                    self._refresh_active_app_banner()  # vuln counts update immediately
                    if self._auto_open: _open_path(self._last_report)
                elif kind == "api_preview":
                    fmt, ops, count = payload
                    for iid in self._ep_tree.get_children(): self._ep_tree.delete(iid)
                    for op in ops:
                        ctype = op.get("ctype") or "—"; secured = "✓" if op.get("secured") else "—"
                        self._ep_tree.insert("","end", values=(op["method"], op["url"], secured, ctype))
                    self._ep_count_lbl.config(text=f"Format: {fmt}  ·  {count} endpoint(s) detected")
                    self._emit_log(f"[api-preview] {fmt} — {count} endpoints")
                elif kind == "static_results":
                    ctx = payload
                    self._static_busy = False
                    for b in getattr(self, "_static_run_btns", []):
                        b.config(state="normal")
                    if ctx is None:
                        if hasattr(self, "_static_count_lbl"):
                            self._static_count_lbl.config(text="Scan failed — see console.")
                    else:
                        if hasattr(self, "_static_sca_tree"):
                            self._render_sca(ctx.get("projects", []))
                        if hasattr(self, "_static_sast_tree"):
                            self._render_sast(ctx.get("files", []))
                        if hasattr(self, "_secrets_box"):
                            self._render_secrets(ctx.get("secrets", {}).get("findings", []))
                        if hasattr(self, "_static_count_lbl"):
                            self._static_count_lbl.config(
                                text=f"SCA {ctx.get('sca_total',0)} · "
                                     f"SAST {ctx.get('code_total',0)} · "
                                     f"Secrets {ctx.get('secrets_total',0)}")
                        if hasattr(self, "_static_open_btn"):
                            self._static_open_btn.config(
                                state="normal" if self._last_static_report else "disabled")
                elif kind == "__done__":
                    self._busy = False; self._update_stop_btn_style(); self._refresh_scan_btn()
                    if not self._any_busy():
                        self._set_status('Ready.'); self._hide_progress()
                        # Reset barras de progreso del pipeline al estado final
                        try:
                            self._pipe_progress_pct = getattr(self, "_pipe_progress_pct", 0.0)
                            # Dejar las barras en su estado final (done/fail) — no reset
                            # Para resetearlas al siguiente scan, se hace en _do_scan via evento
                        except Exception:
                            pass
                elif kind == "__static_done__":
                    # static_results (emitted by _static_scan itself, just before
                    # this fires) already clears _static_busy and re-enables the
                    # Static-tab buttons — this just settles the shared chrome
                    # (Stop button, global status) once *neither* lane is busy.
                    self._static_busy = False; self._update_stop_btn_style()
                    if not self._any_busy():
                        self._set_status('Ready.'); self._hide_progress()
                elif kind == "inv_refresh":
                    inv_tab = getattr(self, "_inv_tab", None)
                    if inv_tab:
                        try: inv_tab.refresh()
                        except Exception: pass
        except queue.Empty: pass
        if self._auth_proc is not None: self._tick_auth_poll()
        self.after(150, self._drain_events)

    def _log_line(self, s: str):
        self._log_widget.configure(state="normal")
        self._log_widget.insert("end", s.rstrip() + "\n")
        max_lines = getattr(self, "_max_log_lines", 2000)
        lines = int(self._log_widget.index("end-1c").split(".")[0])
        if lines > max_lines:
            self._log_widget.delete("1.0", f"{lines - max_lines}.0")
        self._log_widget.see("end")
        self._log_widget.configure(state="disabled")
        if not self._console_visible:
            self._unread_log += 1
            self._console_btn.configure(text=f"▥  Console ({self._unread_log})", fg=T["err"])

    def _any_busy(self) -> bool:
        """True while either independent lane (main pipeline or Static-tab
        quick scan) is running. Used anywhere that needs 'is it safe to do
        X right now' rather than 'is this one specific lane running' —
        the Stop button, the dependency reinstaller, and the idle/'Ready.'
        reset all care about *either* lane, not just the pipeline's."""
        return bool(self._busy) or bool(getattr(self, "_static_busy", False))

    def _update_stop_btn_style(self):
        """Update stop button appearance based on scan state."""
        btn = getattr(self, "_stop_icon_btn", None); wrap = getattr(self, "_stop_icon_wrap", None)
        if not btn: return
        if self._any_busy():  # active: red border (via wrapper), red text, themed bg
            if wrap:
                try: wrap.configure(bg=T["err"])
                except Exception: pass
            btn.configure(fg=T["err"], activeforeground=T["err"], activebackground=T["card_hover"],
                          bg=T["panel_bg"], state="normal")
        else:  # idle: grayed out and disabled — match the bg/fg pattern other disabled buttons use
            if wrap:
                try: wrap.configure(bg=T["muted"])
                except Exception: pass
            btn.configure(fg=T["muted"], activeforeground=T["muted"], activebackground=T["surface2"],
                          bg=T["surface2"], state="disabled")

    def _set_status(self, s: str): self._status_var.set(s)
    def _emit_log(self, s: str):   self._event_queue.put(("log", s))


# ── Loading splash ────────────────────────────────────────────────────────────
def _splash_read_dark_pref() -> bool:
    """Read dark_mode from .scanner_settings.json without importing the app (False if absent/unreadable)."""
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        return bool(data.get("dark_mode", False))
    except Exception:
        return False


class BootSplash(tk.Toplevel):
    """Borderless boot splash mirroring ScannerApp's look (ribbon, amber stripe,
    themed log console). Used both for the initial app launch (own throwaway
    root, see run_boot()) and to re-run the full dependency installer later
    from ScannerApp._fix(), so every install always happens in this one
    window — never inline/silently elsewhere."""

    def __init__(self, master: tk.Misc, modal: bool = True):
        super().__init__(master)
        self.overrideredirect(True)
        try: self.attributes("-topmost", True)
        except Exception: pass
        if modal:
            # NOTE: only do this when `master` is a real, visible window (the
            # _fix() reuse case, master=ScannerApp). If master is the
            # throwaway hidden root used at initial boot (master.withdraw()),
            # calling transient() against a withdrawn master makes Tk/the
            # window manager hide this splash too -- no error, it just never
            # appears on screen. See run_boot(): modal=False for that case.
            try:
                self.transient(master)
            except Exception:
                pass
        _apply_palette(_splash_read_dark_pref())  # palette into T before building widgets
        w, h = 600, 400
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")
        self.configure(bg=T["accent"])
        outer = tk.Frame(self, bg=T["accent"], padx=2, pady=2); outer.pack(fill="both", expand=True)
        c = tk.Frame(outer, bg=T["bg"]); c.pack(fill="both", expand=True)
        # Ribbon header (mirrors ScannerApp._build_ribbon)
        ribbon = tk.Frame(c, bg=T["panel_bg"]); ribbon.pack(fill="x")
        tk.Frame(ribbon, bg=T["accent"], height=2).pack(fill="x", side="top")
        inner_row = tk.Frame(ribbon, bg=T["panel_bg"]); inner_row.pack(fill="x", side="top")
        os_tag = "macOS" if IS_MAC else ("Windows" if IS_WIN else "Linux")
        right_lbl = tk.Frame(inner_row, bg=T["panel_bg"]); right_lbl.pack(side="right", padx=12)
        tk.Label(right_lbl, text=f"{os_tag}  ·  {_detect_user()}", font=(_FUI, 9),
                 bg=T["panel_bg"], fg=T["muted"]).pack(pady=6)
        tk.Frame(ribbon, bg=T["border"], height=1).pack(fill="x", side="bottom")
        body = tk.Frame(c, bg=T["bg"]); body.pack(fill="both", expand=True, padx=22, pady=(10, 14))
        # Rotating globe animation — atmosphere glow, starfield and a soft
        # sphere sheen are drawn once (static); only the meridians, the
        # highlight dot and an orbiting "data packet" satellite redraw each
        # frame, so the extra polish costs almost nothing per tick.
        import math as _math, random as _random
        GR, PAD = 48, 14
        GW = GH = GR * 2 + PAD * 2
        cx, cy = GW // 2, GH // 2
        self._globe_cv = tk.Canvas(body, width=GW, height=GH, bg=T["bg"], bd=0, highlightthickness=0)
        self._globe_cv.pack(side="left", padx=(0, 14))
        self._globe_angle = 0.0

        rnd = _random.Random(7)
        for _ in range(26):  # static starfield
            sx, sy = rnd.randint(0, GW), rnd.randint(0, GH)
            if (sx - cx) ** 2 + (sy - cy) ** 2 < (GR + PAD - 2) ** 2:
                continue
            r = rnd.choice((1, 1, 2))
            self._globe_cv.create_oval(sx - r, sy - r, sx + r, sy + r, fill=T["muted"], outline="")
        for i, stip in enumerate(("gray12", "gray25", "gray50")):  # atmosphere glow rings
            rr = GR + (3 - i) * 4
            self._globe_cv.create_oval(cx - rr, cy - rr, cx + rr, cy + rr, outline=T["accent"], outlinestipple=stip)
        self._globe_cv.create_oval(cx - GR, cy - GR, cx + GR, cy + GR, fill=T["panel_bg"], outline="")
        self._globe_cv.create_oval(cx - GR + 6, cy - GR + 4, cx + GR - 24, cy + GR - 36,
                                   fill=T["accent"], outline="", stipple="gray12")  # glossy sheen

        def _draw_globe(angle):
            cv = self._globe_cv; cv.delete("globe")
            cv.create_oval(cx - GR, cy - GR, cx + GR, cy + GR, outline=T["accent"], width=2, tags="globe")
            for lat_frac in (-0.55, -0.25, 0, 0.25, 0.55):  # fixed latitude lines
                ry = int(GR * _math.sqrt(max(0, 1 - lat_frac**2))); yy = cy + int(GR * lat_frac)
                if ry > 2:
                    cv.create_oval(cx - ry, yy - 4, cx + ry, yy + 4, outline=T["muted"], width=1, tags="globe")
            N = 40
            for lon_offset in (0, 0.5, 1.0, 1.5):  # longitude meridians rotate with angle
                pts = []
                for i in range(N + 1):
                    lat = _math.pi * (i / N - 0.5); lon = angle + _math.pi * lon_offset
                    x3 = _math.cos(lat) * _math.cos(lon); y3 = _math.sin(lat)
                    if _math.cos(lat) * _math.sin(lon) < 0:  # back-face cull
                        continue
                    pts.append((int(cx + GR * x3), int(cy - GR * y3)))
                for j in range(len(pts) - 1):
                    cv.create_line(pts[j], pts[j + 1], fill=T["muted"], width=1, tags="globe")
            hx = cx - int(GR * 0.35); hy = cy - int(GR * 0.38)  # highlight dot
            cv.create_oval(hx - 5, hy - 5, hx + 5, hy + 5, fill=T["accent"], outline="", tags="globe")
            for k, fade in ((3, "gray25"), (2, "gray50"), (1, None), (0, None)):  # orbiting satellite + comet trail
                a = angle * 2.2 - k * 0.22
                ox = cx + (GR + 11) * _math.cos(a); oy = cy + (GR + 11) * 0.32 * _math.sin(a)
                r = 3 if k == 0 else 2
                cv.create_oval(ox - r, oy - r, ox + r, oy + r, fill=T["accent"], outline="",
                               stipple=fade, tags="globe")

        def _spin_globe():
            if self._done or self._error is not None: return
            self._globe_angle = (self._globe_angle + 0.06) % (2 * _math.pi)
            _draw_globe(self._globe_angle); self.after(40, _spin_globe)  # ~25 fps

        _draw_globe(0.0); self.after(40, _spin_globe)
        right_col = tk.Frame(body, bg=T["bg"]); right_col.pack(side="left", fill="both", expand=True)
        self._step_var = tk.StringVar(value="Preparing…")
        self._step_lbl = tk.Label(right_col, textvariable=self._step_var, font=(_FUI, 11, "bold"),
                 bg=T["bg"], fg=T["accent"], anchor="w")
        self._step_lbl.pack(fill="x")
        pb_style = ttk.Style(self)
        try: pb_style.theme_use("clam")
        except tk.TclError: pass
        pb_style.configure("Splash.Horizontal.TProgressbar", troughcolor=T["surface2"], background=T["accent"],
                           bordercolor=T["border"], lightcolor=T["accent"], darkcolor=T["accent"])
        self._pb = ttk.Progressbar(right_col, style="Splash.Horizontal.TProgressbar", mode="determinate", maximum=100)
        self._pb.pack(fill="x", pady=(6, 10))
        logwrap = tk.Frame(right_col, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        logwrap.pack(fill="both", expand=True)
        tk.Frame(logwrap, bg=T["accent"], height=1).pack(fill="x", side="top")
        self._log = tk.Text(logwrap, bg=T["panel_bg"], fg=T["muted"], relief="flat", font=(_FMONO, 9),
                            padx=10, pady=8, height=8, state="disabled", wrap="none",
                            insertbackground=T["text"], selectbackground=T["accent"], selectforeground=T["button_fg"])
        self._log.tag_configure("warn", foreground=T["accent"])
        self._log.tag_configure("err", foreground=T["err"])
        sb = tk.Scrollbar(logwrap, command=self._log.yview, bg=T["panel_bg"], troughcolor=T["surface2"],
                          relief="flat", bd=0)
        self._log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); self._log.pack(fill="both", expand=True)
        self._q: queue.Queue = queue.Queue()
        self._done = False
        self._error: Optional[str] = None
        self._warnings: list[tuple[str, str]] = []
        self.after(60, self._pump)

    def progress(self, kind, payload):  # progress callback used by _load_runtime (worker thread)
        self._q.put((kind, payload))

    def _append(self, text: str, tag: Optional[str] = None):
        self._log.configure(state="normal")
        start = self._log.index("end-1c")
        self._log.insert("end", text.rstrip() + "\n")
        if tag:
            self._log.tag_add(tag, start, "end-1c")
        lines = int(self._log.index("end-1c").split(".")[0])  # keep the last ~200 lines
        if lines > 200:
            self._log.delete("1.0", f"{lines - 200}.0")
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
                    # Optional-component issues are logged with a "⚠" prefix
                    # (see _warn() in _load_runtime) and fatal ones with
                    # "FATAL"/"ERROR" — color them so they don't blend into
                    # the rest of the (muted gray) boot chatter.
                    tag = ("err" if text.startswith(("FATAL", "ERROR")) else
                           "warn" if text.startswith("⚠") else None)
                    self._append(text, tag)
                elif kind == "warn_summary":
                    self._warnings = list(payload)
                elif kind == "error":
                    self._error = str(payload)
                elif kind == "done":
                    if self._warnings:
                        self._step_var.set(f"⚠  Done with {len(self._warnings)} warning(s) — check the log")
                    else:
                        self._step_var.set("✔  Ready — launching…")
                    self._pb.configure(value=100); self._done = True
        except queue.Empty:
            pass
        if self._done or self._error is not None:
            # Give the user a moment to actually notice the warning summary
            # (and the colored log lines) before this window disappears —
            # the normal "all good" close stays snappy.
            delay = 1800 if (self._done and self._warnings) else 280
            self.after(delay, self.destroy); return  # close just this splash window
        self.after(60, self._pump)


def run_boot(master: Optional[tk.Misc] = None) -> tuple[Optional[str], list[tuple[str, str]]]:
    """Show the boot splash, run _load_runtime in a worker thread, and block
    until done — returns (error, warnings):
      - error: None on success, or an error string if a *required* dependency
        (a pip package, or the engine modules themselves) failed to load.
      - warnings: (label, detail) pairs for *optional* components — Node/npm,
        git-secrets, Snyk CLI — that couldn't be installed/verified. These
        never block the app from starting; the splash flags them inline
        (colored log lines) and the caller can surface them once more after
        launch so they don't go unnoticed.

    `master`:
      - None (initial app launch, see main() below): a throwaway hidden Tk
        root is created to host the splash.
      - an existing widget/root (e.g. ScannerApp itself, from _fix()): the
        splash becomes a modal Toplevel over it, so re-installing missing
        dependencies after the app is already open reuses this exact same
        window/animation instead of installing things inline elsewhere.

    Every dependency this program installs — pip packages, Node.js/npm,
    git-secrets, Snyk CLI — funnels through _load_runtime(), so this single
    function is the only place any installer ever runs.
    """
    own_root = master is None
    if own_root:
        master = tk.Tk()
        master.withdraw()
    splash = BootSplash(master, modal=not own_root)
    holder: dict = {"error": None, "warnings": []}

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
    master.wait_window(splash)  # blocks (processing events) until the splash closes
    if own_root:
        try: master.destroy()
        except Exception: pass
    return holder["error"], holder["warnings"]


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    err, boot_warnings = run_boot()  # 1) real loading splash while heavy deps + git-secrets are fetched
    if err:
        msg = ("Scanner could not load its dependencies:\n\n" + err +
               "\n\nUsually a missing package or corporate TLS proxy.")
        try:
            root = tk.Tk(); root.withdraw()
            messagebox.showerror(f"{APP_BRAND_NAME} — startup failed", msg)
        except Exception:
            print(msg, file=sys.stderr)
        return
    try:  # 2) launch the main application
        app = ScannerApp(boot_warnings=boot_warnings)
    except Exception as e:
        import traceback
        msg = (f"Scanner could not start:\n\n{e!r}\n\n"
               "Usually a missing package or corporate TLS proxy.\n\n" + traceback.format_exc())
        try:
            root = tk.Tk(); root.withdraw()
            messagebox.showerror(f"{APP_BRAND_NAME} — startup failed", msg)
        except Exception:
            print(msg, file=sys.stderr)
        raise
    app.mainloop()


if __name__ == "__main__":
    main()