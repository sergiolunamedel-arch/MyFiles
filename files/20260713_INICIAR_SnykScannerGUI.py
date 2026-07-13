from __future__ import annotations

import os, sys, shutil, subprocess
from contextlib import contextmanager
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


_BOOT_DEPS = [
    ("jinja2",            "Jinja2",            "Motor de plantillas de reporte"),
    ("selenium",          "selenium",          "Automatización de navegador (DAST)"),
    ("webdriver_manager", "webdriver-manager", "Descargador de WebDriver"),
    ("pynput",            "pynput",            "Escucha de atajos globales (grabador)"),
    ("yaml",              "PyYAML",            "Parseo de especificaciones YAML (OpenAPI/Swagger)"),
    ("requests",          "requests",          "Cliente HTTP"),
]
_RUNTIME_READY = False


def _load_runtime(progress=None) -> list[tuple[str, str]]:
    global _RUNTIME_READY

    _log_lines: list[str] = []
    _boot_started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _boot_log_path = DATA_DIR / "boot_dependencies.log"

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
        total = len(_BOOT_DEPS) + 5
        step = 0
        for import_name, pip_name, label in _BOOT_DEPS:
            step += 1
            if progress: progress("step", (step, total, f"{label} ({import_name})"))
            _ensure(import_name, pip_name, log=_log)
            _flush_log()

        step += 1
        if progress: progress("step", (step, total, "Node.js + npm (entorno JavaScript)"))
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
        if progress: progress("step", (step, total, "git-secrets (escáner de secretos)"))
        try:
            import static_scanner
            static_scanner.ensure_git_secrets(log=_log)
        except Exception as e:
            _warn("git-secrets", repr(e))
        _flush_log()

        step += 1
        if progress: progress("step", (step, total, "Snyk CLI (escáner de vulnerabilidades)"))
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
        if progress: progress("step", (step, total, "Cargando motor de escaneo…"))
        g = globals()
        import static_scanner as _ss
        for n in ("CheckResult", "check_python", "check_node", "check_npm",
                  "check_snyk", "check_auth", "install_node", "install_snyk",
                  "start_snyk_auth", "run_snyk_test", "run_snyk_code",
                  "clear_snyk_credentials",
                  "SnykScanError", "ensure_snyk_ready", "setup_proxy_tls_env",
                  "export_sarif", "export_merged_json",
                  "scan_path", "write_secrets_report", "ensure_git_secrets",
                  "get_git_secrets_status", "get_engine_label",
                  "get_snyk_token", "get_snyk_auth_scheme",
                  "set_probely_key", "get_probely_key", "get_probely_auth_scheme",
                  "_which", "_run"):
            g[n] = getattr(_ss, n)
        g["static_scanner"] = _ss
        g["secrets_scanner"] = _ss
        import snyk_dast_api as _dast
        for n in ("DastConfig", "ApiConfig", "run_dast", "run_api", "_make_driver",
                  "_MACRO_JS", "_MACRO_DRAIN_JS", "_LOGOUT_CAPTURE_JS", "detect_browsers",
                  "_replay_login_macro", "analyze_login_macro", "prewarm_driver",
                  "record_macro_work", "record_logout_work", "test_logout_work",
                  "_api_load_spec", "_api_base_url", "_api_operations", "_make_opener",
                  "check_snyk_api_web", "fetch_scan_profiles"):
            g[n] = getattr(_dast, n)
        import report_engine as _rep
        for n in ("build_cumulative_context", "export_csv", "render_html",
                  "update_history_after_scan", "render_remediation_history",
                  "add_remediation_action", "load_history", "ScanStateStore"):
            g[n] = getattr(_rep, n)
        _wire_mixin_globals()

        step += 1
        if progress: progress("step", (step, total, "Pre-calentando Snyk CLI (Node.js)…"))
        try:
            _snyk_bin = getattr(_ss, "_which", lambda x: None)("snyk") or "snyk"
            subprocess.run([_snyk_bin, "--version"],
                           capture_output=True, timeout=15)
            _log("snyk prewarm: CLI cargado en caché del SO")
        except Exception as e:
            _log(f"snyk prewarm: {e!r} (no crítico — se omite)")
        _flush_log()

        _RUNTIME_READY = True
        _log("Motor listo.")
        _flush_log("completed successfully" if not _warnings else f"completed with {len(_warnings)} warning(s)")
        if _warnings and progress:
            try: progress("warn_summary", list(_warnings))
            except Exception: pass
        return list(_warnings)
    except Exception as e:
        _log(f"FATAL: {e!r}")
        _flush_log("failed")
        raise


import json, queue, getpass, re as _re, threading, time, webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Callable, Optional

def _native_msgbox(title: str, text: str) -> None:
    """Show a message without needing tkinter (which may not exist yet)."""
    if IS_WIN:
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, text, title, 0x00000030)
            return
        except Exception:
            pass
    print(f"\n=== {title} ===\n{text}\n")


def _run_elevated_and_wait(exe: str, params: str, timeout_ms: int = 900_000) -> bool:
    """Run `exe params` elevated (UAC prompt) and block until it finishes."""
    import ctypes
    from ctypes import wintypes

    class _SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong),
            ("hwnd", wintypes.HWND), ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
            ("lpClass", wintypes.LPCWSTR), ("hkeyClass", ctypes.c_void_p),
            ("dwHotKey", wintypes.DWORD), ("hIconOrMonitor", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]

    sei = _SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = 0x00000040 | 0x00000100  # SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
    sei.lpVerb = "runas"
    sei.lpFile = exe
    sei.lpParameters = params
    sei.nShow = 0
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        return False
    if sei.hProcess:
        result = ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, timeout_ms)
        ctypes.windll.kernel32.CloseHandle(sei.hProcess)
        return result == 0
    return True


def _repair_tkinter_windows(log=print) -> bool:
    """Best-effort: re-run the official python.org installer for THIS exact
    Python install, requesting only the 'tcl/tk and IDLE' feature. Running the
    same-version installer against an existing install performs a silent
    modify/repair instead of a fresh side-by-side install."""
    import platform, tempfile, urllib.request

    ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    arch = "amd64" if platform.architecture()[0] == "64bit" else "win32"
    target_dir = sys.prefix
    program_files = [os.environ.get("ProgramFiles", r"C:\Program Files"),
                      os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")]
    all_users = target_dir.lower().startswith(tuple(p.lower() for p in program_files))

    installer, tmp_dir = None, None
    cache_root = Path(os.environ.get("LOCALAPPDATA", "")) / "Package Cache"
    if cache_root.exists():
        installer = next(cache_root.glob(f"**/python-{ver}*{arch}.exe"), None)

    if installer is None:
        url = f"https://www.python.org/ftp/python/{ver}/python-{ver}-{arch}.exe"
        try:
            tmp_dir = Path(tempfile.mkdtemp(prefix="tkfix_"))
            installer = tmp_dir / "python_installer.exe"
            log(f"Descargando instalador oficial de Python {ver}…")
            urllib.request.urlretrieve(url, installer)
        except Exception as e:
            log(f"No se pudo descargar el instalador: {e!r}")
            return False

    args = ["/quiet", f"InstallAllUsers={'1' if all_users else '0'}",
            "Include_tcltk=1", "Include_test=0", f'TargetDir={target_dir}']
    try:
        log("Reparando Python para agregar tcl/tk (puede tardar 1-2 min)…")
        if all_users:
            params = " ".join(f'"{a}"' if " " in a else a for a in args)
            ok = _run_elevated_and_wait(str(installer), params)
        else:
            ok = subprocess.run([str(installer)] + args, timeout=900).returncode == 0
    except Exception as e:
        log(f"Fallo al ejecutar el instalador: {e!r}")
        ok = False
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    return ok


def _ensure_tkinter() -> None:
    """Runs before the first `import tkinter`. If tkinter is missing —
    normally because 'tcl/tk and IDLE' was left unchecked when Python was
    installed — try to repair it automatically on Windows, then retry."""
    try:
        import tkinter  # noqa: F401
        return
    except ImportError:
        pass

    if not IS_WIN:
        _native_msgbox(
            "SecDevOps Banco Base — falta tkinter",
            "Este equipo no tiene el modulo 'tkinter' de Python.\n\n"
            "Instalelo y vuelva a abrir el programa:\n"
            "  Debian/Ubuntu:  sudo apt install python3-tk\n"
            "  Fedora/RHEL:    sudo dnf install python3-tkinter\n"
            "  macOS (brew):   brew install python-tk")
        sys.exit(1)

    _native_msgbox(
        "SecDevOps Banco Base — reparando Python",
        "Falta el componente 'tcl/tk' de Python (necesario para la interfaz "
        "grafica). Se intentara repararlo automaticamente ahora.\n\n"
        "Esto puede tardar uno o dos minutos y puede pedir permisos de "
        "administrador. No cierre esta ventana.")

    try:
        repaired = _repair_tkinter_windows()
    except Exception:
        repaired = False

    if repaired:
        try:
            import tkinter  # noqa: F401
            return
        except ImportError:
            pass

    _native_msgbox(
        "SecDevOps Banco Base — reparacion manual necesaria",
        "No fue posible instalar tcl/tk automaticamente.\n\n"
        "Solucion manual:\n"
        "1) Panel de control -> Programas y caracteristicas\n"
        "2) Seleccione su version de Python -> 'Modificar'\n"
        "3) Marque la casilla 'tcl/tk and IDLE'\n"
        "4) Finalice la instalacion y vuelva a abrir este programa.")
    sys.exit(1)


_ensure_tkinter()

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


SCRIPT_DIR         = Path(__file__).resolve().parent
CORE_DIR           = SCRIPT_DIR / "core"
IMAGES_DIR         = SCRIPT_DIR / "images"
DATA_DIR           = SCRIPT_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOGO_PATH          = IMAGES_DIR / "Logo.png"
# Used specifically by the wizard's authentication step (fase de autenticación),
# which must show Snyk.png — not interchangeable with LOGO_PATH.
AUTH_LOGO_PATH     = IMAGES_DIR / "Snyk.png"
if CORE_DIR.exists() and str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))
APP_BRAND_NAME      = "SecDevOps Banco Base"
# No default target folder: the user must explicitly pick what to scan.
# (Was SCRIPT_DIR / "Vulnerable", which prefilled a bundled test repo on every
# launch and showed up in both the Scan and Static tabs.)
DEFAULT_TARGET     = ""
DEFAULT_REPORTS    = SCRIPT_DIR / "Reports"
SETTINGS_FILE      = DATA_DIR / ".scanner_settings.json"
SESSION_FILE       = DATA_DIR / ".scanner_session.json"
AUTH_POLL_INTERVAL = 2
AUTH_POLL_TIMEOUT  = 300

if IS_MAC:     _FUI, _FMONO = "SF Pro Text", "Menlo"
elif IS_LINUX: _FUI, _FMONO = "DejaVu Sans", "DejaVu Sans Mono"
else:          _FUI, _FMONO = "Segoe UI", "Cascadia Mono"

_PALETTE_LIGHT = {
    "bg":        "#f5f6f8", "panel_bg":  "#ffffff", "surface2":  "#eef1f7",
    "accent":    "#F5A800", "accent_hi": "#c48700", "button_fg": "#ffffff",
    "accent2":   "#c8102e", "accent2_hi":"#a00d24",
    "text":      "#0d1b2a", "muted":     "#5a6475", "border":    "#dde2ec",
    "border_bg": "#dde2ec",
    "border2":   "#1a3a5c",
    "shadow":    "#5a6475",
    "ok":        "#1a7a4a", "err":       "#c8102e", "card_hover":"#eef1f7",
    "pill_run_bg":"#002060","pill_run_fg":"#c0ccee",
    "pill_ok_bg": "#0c4a2b","pill_ok_fg": "#a7f0c8",
    "pill_bad_bg":"#7a0c1c","pill_bad_fg":"#fdb8c0",
    "pill_idle_bg":"#dde2ec","pill_idle_fg":"#5a6475",
    "surface3":   "#e4e8f0",
    "pill_crit_bg":"#fcebeb","pill_crit_fg":"#791f1f",
    "pill_high_bg":"#faeeda","pill_high_fg":"#633806",
    "pill_med_bg": "#f1efe8","pill_med_fg": "#444441",
    "pill_low_bg": "#f1efe8","pill_low_fg": "#888780",
}
_PALETTE_DARK = {
    "bg":        "#0f1012", "panel_bg":  "#16181c", "surface2":  "#1e2127",
    "accent":    "#F5A800", "accent_hi": "#c48700", "button_fg": "#000000",
    "accent2":   "#c8102e", "accent2_hi":"#a00d24",
    "text":      "#f0f1f3", "muted":     "#6b7280", "border":    "#252830",
    "border_bg": "#252830",
    "border2":   "#3d6899",
    "shadow":    "#000000",
    "ok":        "#22c55e", "err":       "#ef4444", "card_hover":"#1e2127",
    "pill_run_bg":"#0a1840","pill_run_fg":"#7a9cee",
    "pill_ok_bg": "#0a2818","pill_ok_fg": "#4ade80",
    "pill_bad_bg":"#3b0f0f","pill_bad_fg":"#fca5a5",
    "pill_idle_bg":"#252830","pill_idle_fg":"#6b7280",
    "surface3":   "#252830",
    "pill_crit_bg":"#3b0f0f","pill_crit_fg":"#fca5a5",
    "pill_high_bg":"#3b2508","pill_high_fg":"#fdba74",
    "pill_med_bg": "#1e2127","pill_med_fg": "#9ca3af",
    "pill_low_bg": "#1e2127","pill_low_fg": "#6b7280",
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
    
    if proc is None:
        return
    pid = proc.pid
    try:
        if IS_WIN:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                           capture_output=True, timeout=5)
        else:
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


_ROLE_BG = {_PALETTE_LIGHT[k]: k for k in ("bg", "panel_bg", "surface2", "border_bg", "shadow", "border2")}
_ROLE_BG.update({_PALETTE_DARK[k]: k for k in ("bg", "panel_bg", "surface2", "border_bg", "shadow", "border2")})
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
    T["button_fg"] = "#000000" if dark else "#ffffff"


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
    tag = "odd" if len(tree.get_children()) % 2 else "even"
    tree.insert("", "end", iid=str(d), values=vals, tags=(tag,))
    return True


def _tree_sort_col(tree: "ttk.Treeview", col: str, reverse: bool) -> None:
    """Generic toggle-sort for any Treeview built by _make_tree.
    Tries numeric sort first, falls back to case-insensitive string sort."""
    data = [(tree.set(iid, col), iid) for iid in tree.get_children()]

    def _key(x: tuple) -> tuple:
        v = x[0]
        try:
            return (0, float(v))
        except (ValueError, TypeError):
            return (1, str(v).lower())

    data.sort(key=_key, reverse=reverse)
    for idx, (_, iid) in enumerate(data):
        tree.move(iid, "", idx)
    tree.heading(col, command=lambda c=col: _tree_sort_col(tree, c, not reverse))


def _make_tree(parent, cols, headings, height) -> "ttk.Treeview":
    outer = tk.Frame(parent, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
    outer.pack(side="left", fill="both", expand=True)
    tk.Frame(outer, bg=T["accent"], height=2).pack(fill="x", side="top")
    tf = tk.Frame(outer, bg=T["panel_bg"]); tf.pack(fill="both", expand=True)
    tree = ttk.Treeview(tf, columns=cols, show="headings", height=height)
    for c, (txt, w) in zip(cols, headings):
        tree.heading(c, text=txt,
                     command=lambda col=c: _tree_sort_col(tree, col, False))
        tree.column(c, width=w, anchor="w")
    tree.tag_configure("even", background=T["panel_bg"])
    tree.tag_configure("odd", background=T["surface2"])
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
        app._show_error_popup("Eliminar", f"Failed:\n{e}"); return
    for cb in on_done: cb()


def _open_selected_report_folder(app, tree: "ttk.Treeview") -> None:
    """Open the folder of the report selected in `tree` (never the reports
    root) — shared by the Recent Scans card and ReportsViewer."""
    d = _tree_selected_dir(tree)
    if not d:
        app._show_info_popup("Abrir carpeta", "Seleccione un reporte primero."); return
    _open_path(d)


def _monitor_wh(widget) -> tuple:
    """Return (width, height) of the monitor that *widget* currently lives on.
    On Windows uses MonitorFromWindow + GetMonitorInfoW so the result is always
    the *current* monitor, even after the window has been dragged to a different
    screen.  Falls back to winfo_screenwidth/height on other platforms or on
    any Win32 error."""
    if IS_WIN:
        try:
            import ctypes, struct
            hwnd = int(widget.wm_frame(), 16)
            hmon = ctypes.windll.user32.MonitorFromWindow(hwnd, 2)
            mi = (ctypes.c_uint32 * 10)()
            mi[0] = ctypes.sizeof(mi)
            ctypes.windll.user32.GetMonitorInfoW(hmon, mi)
            l, t, r, b = struct.unpack_from("<iiii", bytes(mi), 4)
            return r - l, b - t
        except Exception:
            pass
    return widget.winfo_screenwidth(), widget.winfo_screenheight()


def _center_over(master, win, w_pct: float, h_pct: float) -> None:
    """Size *win* as a fraction of the *current* monitor and centre it over
    *master*.  Queries the actual monitor the parent lives on so the popup
    stays proportional and correctly placed after the window is moved to a
    monitor with a different resolution."""
    master.update_idletasks()
    mw, mh = _monitor_wh(master)
    w, h = int(mw * w_pct), int(mh * h_pct)
    px = master.winfo_rootx()
    py = master.winfo_rooty()
    pw = master.winfo_width()
    ph = master.winfo_height()
    x = px + (pw - w) // 2
    y = py + (ph - h) // 2
    win.geometry(f"{w}x{h}+{x}+{y}")


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
            try:
                if not win.winfo_ismapped():
                    win.deiconify()
                win.lift()
            except Exception: pass

    def _on_focus_out(e):
        """Withdraw the popup when the whole app loses focus to another program.
        A short delay lets Tk settle focus internally (e.g. moving between
        widgets within the same app); we only withdraw when focus_get()
        returns None AND focus is not inside win itself.

        Without the win-focus guard, calling win.focus_force() from _create_popup
        fires <FocusOut> on parent, parent.focus_get() returns None (focus is on
        the Toplevel win, not on a parent widget), and win.withdraw() is called
        100 ms later — hiding the popup immediately after it opens.  Long-lived
        interactive popups (e.g. the wizard) are the only ones that stay open long
        enough for the after(100) to fire, which is why they are uniquely affected.
        """
        if win.winfo_exists():
            def _check():
                if win.winfo_exists():
                    if getattr(win, "_dialog_guard_active", False):
                        # A native dialog opened from inside this popup (e.g. the
                        # "add folder/file" file picker in the wizard) currently owns
                        # focus. That isn't the user switching to another program, so
                        # don't withdraw the popup — see _popup_dialog_guard().
                        return
                    try:
                        try:
                            focused = win.focus_displayof()
                            if focused is not None:
                                w = focused
                                while w is not None:
                                    if w is win:
                                        return
                                    w = getattr(w, "master", None)
                        except Exception:
                            pass
                        if parent.focus_get() is None:
                            win.withdraw()
                    except Exception:
                        pass
            parent.after(100, _check)

    def _on_unmap(e):
        if e.widget is parent and win.winfo_exists():
            try: win.withdraw()
            except Exception: pass

    def _on_map(e):
        if e.widget is parent and win.winfo_exists():
            try: win.deiconify(); win.lift()
            except Exception: pass

    return {"<FocusIn>":  parent.bind("<FocusIn>",  _on_focus,     "+"),
            "<FocusOut>": parent.bind("<FocusOut>",  _on_focus_out, "+"),
            "<Unmap>":    parent.bind("<Unmap>",     _on_unmap,     "+"),
            "<Map>":      parent.bind("<Map>",        _on_map,       "+")}


@contextmanager
def _popup_dialog_guard(win: tk.Toplevel):
    """Wrap a native dialog call (filedialog.askdirectory/askopenfilename/etc.) opened
    from inside a popup built by _create_popup (e.g. the wizard).

    Native dialogs run outside the Tk widget tree, so opening one takes focus away from
    both the app root and the popup itself. _popup_follow_parent's <FocusOut> handler
    would otherwise treat that as "the user switched to another program" and withdraw
    the popup ~100ms later — which is why picking a static-analysis path used to send
    the wizard to the background (or close it) until the user clicked it again.

    This suspends that auto-withdraw for the duration of the `with` block, then re-lifts
    and re-focuses the popup afterward so it stays in front without an extra click.
    """
    win._dialog_guard_active = True
    try:
        yield
    finally:
        win._dialog_guard_active = False
        try:
            if win.winfo_exists():
                win.deiconify()
                win.lift()
                win.focus_force()
        except Exception:
            pass


def _themed_btn(parent, text, cmd, *, font, bg, fg, hover_bg, hover_fg, **kw):
    """A flat hand2 tk.Button used by ReportsViewer header/footer rows."""
    return tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg,
                     activebackground=hover_bg, activeforeground=hover_fg,
                     font=font, relief="flat", cursor="hand2", bd=0, **kw)


def _apply_panel_chrome(win: "tk.Toplevel", geo_string: str | None = None) -> "tk.Frame":
    """Double-outline + real semi-transparent drop-shadow for borderless panels.

    Shadow technique: a second Toplevel placed _SD px to the right and below
    the panel, with wm_attributes('-alpha', 0.35) for genuine transparency.
    The panel Toplevel itself stays fully opaque.  The shadow window is:
      • overrideredirect so it has no title bar
      • lower()ed behind the panel
      • destroyed when the panel is destroyed
      • updated whenever the panel moves (via <Configure> binding)

    Returns the innermost content Frame for callers to pack widgets into.
    """
    _SD = 10

    win.update_idletasks()
    geo = geo_string or win.geometry()
    m = _re.match(r"(\d+)x(\d+)\+(-?\d+)\+(-?\d+)", geo)
    if not m:
        win.configure(bg=T["accent"])
        b = tk.Frame(win, bg=T["accent"], padx=2, pady=2)
        b.pack(fill="both", expand=True)
        c = tk.Frame(b, bg=T["bg"]); c.pack(fill="both", expand=True)
        return c

    gw, gh, gx, gy = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))

    root = win.winfo_toplevel().master or win
    try:
        root = win.nametowidget(".")
    except Exception:
        pass
    shad = tk.Toplevel(root)
    shad.overrideredirect(True)
    shad.configure(bg=T["shadow"])
    shad.geometry(f"{gw}x{gh}+{gx + _SD}+{gy + _SD}")
    shad.lower(win)
    win._shadow_win = shad
    try:
        shad.attributes("-alpha", 0.35)
    except tk.TclError:
        pass
    win.bind("<Destroy>", lambda e: (shad.destroy() if shad.winfo_exists() else None), add="+")

    def _sync_shadow(e=None):
        if not win.winfo_exists() or not shad.winfo_exists():
            return
        try:
            x = win.winfo_rootx() + _SD
            y = win.winfo_rooty() + _SD
            w = win.winfo_width()
            h = win.winfo_height()
            shad.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass
    win.bind("<Configure>", _sync_shadow, add="+")

    def _on_map(e):
        if e.widget is win and shad.winfo_exists():
            try:
                shad.deiconify()
                _sync_shadow()
                shad.lower(win)
            except Exception: pass
    def _on_unmap(e):
        if e.widget is win and shad.winfo_exists():
            try: shad.withdraw()
            except Exception: pass
    win.bind("<Map>",   _on_map,   add="+")
    win.bind("<Unmap>", _on_unmap, add="+")

    border2 = tk.Frame(win, bg=T["border2"])
    border2.place(x=0, y=0, relwidth=1.0, relheight=1.0)

    border = tk.Frame(border2, bg=T["accent"])
    border.place(x=1, y=1, relwidth=1.0, relheight=1.0, width=-2, height=-2)

    content = tk.Frame(border, bg=T["bg"])
    content.place(x=1, y=1, relwidth=1.0, relheight=1.0, width=-2, height=-2)
    return content


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
        content = _apply_panel_chrome(self)

        hb = T["panel_bg"]
        hdr = tk.Frame(content, bg=hb, padx=30, pady=14); hdr.pack(fill="x")
        row = tk.Frame(hdr, bg=hb); row.pack(fill="x")
        xbtn = tk.Label(row, text="✕", font=(_FUI, 13, "bold"), bg=hb, fg=T["muted"], cursor="hand2", padx=6)
        xbtn.pack(side="right")
        xbtn.bind("<Button-1>", lambda e: _close())
        xbtn.bind("<Enter>", lambda e: xbtn.config(fg=T["err"]))
        xbtn.bind("<Leave>", lambda e: xbtn.config(fg=T["muted"]))
        tk.Label(row, text="📋  Historial de reportes", font=(_FUI, 15, "bold"), bg=hb, fg=T["accent"]).pack(side="left")
        tk.Label(row, text=str(root_path), font=(_FUI, 10, "italic"), bg=hb, fg=T["muted"]).pack(side="left", padx=(12, 0))
        search_row = tk.Frame(hdr, bg=hb); search_row.pack(fill="x", pady=(10, 0))
        tk.Label(search_row, text="🔎", font=(_FUI, 11), bg=hb, fg=T["muted"]).pack(side="left")
        self._filter_var = tk.StringVar(value="")
        search_entry = ttk.Entry(search_row, textvariable=self._filter_var, width=40)
        search_entry.pack(side="left", padx=(6, 0))
        tk.Label(search_row, text="filtrar por aplicación, modo o destino",
                 font=(_FUI, 9), bg=hb, fg=T["muted"]).pack(side="left", padx=(8, 0))
        self._filter_var.trace_add("write", lambda *_: self._refresh())
        tk.Frame(content, bg=T["border_bg"], height=1).pack(fill="x")

        tree_wrap = tk.Frame(content, bg=T["bg"]); tree_wrap.pack(fill="both", expand=True, padx=18, pady=(14, 6))
        cols = ("app", "when", "mode", "total", "critical", "high", "medium", "low", "target")
        self._tree = _make_tree(tree_wrap, cols, [
            ("Aplicación", 130), ("Generado", 150), ("Modo", 80), ("Total", 55), ("Crit", 45),
            ("Alto", 45), ("Med", 45), ("Bajo", 45), ("Objetivo", 300)], height=16)
        self._tree.bind("<Double-1>", lambda _: self._open_html())

        tk.Frame(content, bg=T["border_bg"], height=1).pack(fill="x")
        foot = tk.Frame(content, bg=T["panel_bg"], padx=20, pady=10); foot.pack(fill="x")
        self._app._btn(foot, "✕  Cerrar", _close, kind="accent").pack(side="right", padx=(6, 0))
        for txt, cmd in [("🗑 Eliminar", self._delete), ("🧬 Exportar SARIF…", self._export_sarif),
                         ("💾 Exportar CSV…", self._export_csv), ("📁 Abrir carpeta", self._open_selected),
                         ("▶ Abrir HTML", self._open_html)]:
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
                found.append((entry, "—"))
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
        else: self._app._show_warn_popup("Abrir HTML", f"No HTML report in:\n{d}")

    def _export_csv(self):
        d = self._sel()
        if not d: return
        src = next(iter(sorted(d.glob("*.zip"))), None) \
            or (d / "findings.csv" if (d / "findings.csv").exists() else None) \
            or next(iter(sorted(d.glob("*.csv"))), None)
        if not src or not src.exists():
            self._app._show_warn_popup("Exportar CSV", f"No CSV/ZIP export in:\n{d}"); return
        ext = src.suffix
        path = filedialog.asksaveasfilename(title="Exportar CSV", defaultextension=ext,
            initialdir=str(d), initialfile=src.name,
            filetypes=[("ZIP bundle", "*.zip"), ("CSV", "*.csv"), ("All", "*.*")])
        if not path: return
        shutil.copyfile(src, path)
        self._app._show_info_popup("Exportar CSV", f"Wrote {path}")

    def _export_sarif(self):
        d = self._sel()
        if not d: return
        if not any((d / n).exists() for n in ("snyk_test.json", "snyk_code.json", "dast.json", "api.json")):
            self._app._show_warn_popup("Exportar SARIF", f"No raw scan output in:\n{d}"); return
        try:
            sarif = export_sarif(d); export_merged_json(d)
        except Exception as e:
            self._app._show_error_popup("Exportar SARIF", f"Failed:\n{e}"); return
        if not sarif:
            self._app._show_warn_popup("Exportar SARIF", "Nothing to export — no findings were assembled."); return
        path = filedialog.asksaveasfilename(title="Exportar SARIF", defaultextension=".sarif",
            initialdir=str(d), initialfile="findings.sarif", filetypes=[("SARIF", "*.sarif *.json"), ("All", "*.*")])
        if not path:
            self._app._show_info_popup("Exportar SARIF", f"SARIF written in report folder:\n{sarif}"); return
        try:
            shutil.copyfile(sarif, path)
        except Exception as e:
            self._app._show_error_popup("Exportar SARIF", f"Could not copy:\n{e}"); return
        self._app._show_info_popup("Exportar SARIF", f"Wrote {path}")

    def _delete(self):
        _delete_selected_report(self._app, self._tree, self._refresh)


import gui_scan_tab, gui_dast_tab, gui_api_tab, gui_static_tab, gui_reports_tab, gui_apps_tab, gui_wizard
from gui_scan_tab import _ScanTabMixin
from gui_dast_tab import _DastTabMixin
from gui_api_tab import _ApiTabMixin
from gui_static_tab import _StaticTabMixin
from gui_reports_tab import _ReportsTabMixin
from gui_apps_tab import _AppsTabMixin
from gui_wizard import _WizardMixin


_MIXIN_MODULES = (gui_scan_tab, gui_dast_tab, gui_api_tab,
                  gui_static_tab, gui_reports_tab, gui_apps_tab, gui_wizard)


def _wire_mixin_globals() -> None:
    shared = globals()
    for mod in _MIXIN_MODULES:
        for k, v in shared.items():
            if not k.startswith("__"):
                mod.__dict__[k] = v


class ScannerApp(_WizardMixin, _ScanTabMixin, _DastTabMixin, _ApiTabMixin, _StaticTabMixin,
                 _ReportsTabMixin, _AppsTabMixin, tk.Tk):


    def __init__(self, boot_warnings: Optional[list[tuple[str, str]]] = None):
        super().__init__()
        self.title(APP_BRAND_NAME)
        self.configure(bg=T["bg"])
        try:
            self._window_icon_img = tk.PhotoImage(file=str(LOGO_PATH))
            self.iconphoto(True, self._window_icon_img)
        except Exception:
            pass
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
        self._orch_busy = False
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
        self._wizard_seen = False
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
            self._log_line("[boot]   Full detail in data/boot_dependencies.log.")
        self.after(150, self._drain_events)
        self.after(200, self._auto_load_last_app)
        self.after(300, self._kick_auth_check)
        # Paint the Probely badge from restored state, and if a key was restored
        # from settings, validate it quietly in the background so the badge goes
        # green without the user reopening the popup.
        self.after(350, self._update_probely_badge_style)
        self.after(900, lambda: (self._validate_probely_key()
                                 if self._probely_configured() else None))
        self.after(1200, lambda: threading.Thread(
            target=lambda: prewarm_driver(self._collect_dast_cfg(), self._emit_log)
            if _RUNTIME_READY else None, daemon=True).start())
        self.after(700, self._check_unclean_shutdown)
        self.after(1800, self._maybe_open_wizard_on_first_launch)

    def _load_settings(self):
        if not SETTINGS_FILE.exists(): return
        try: data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except Exception: return
        if "dark_mode" in data:
            self._dark_mode = bool(data["dark_mode"]); _apply_palette(self._dark_mode)
        if data.get("reports_root"):
            candidate = Path(data["reports_root"])
            try:
                # Validar que la ruta guardada realmente se pueda usar en ESTA
                # PC. Si el archivo de configuración viaja con la app a otra
                # máquina (copia manual, USB, etc.) y la ruta apunta a una
                # unidad que aquí no existe (p.ej. D:\... en una PC sin disco
                # D:), el mkdir fallaba con WinError 3 y tumbaba el arranque.
                candidate.mkdir(parents=True, exist_ok=True)
                self._reports_root = candidate
            except OSError as e:
                self._reports_root = DEFAULT_REPORTS
                self._boot_warnings.append((
                    "Carpeta de reportes",
                    f"La ruta guardada '{candidate}' no está disponible en esta PC "
                    f"({e!r}). Se usará la carpeta por defecto junto al programa: "
                    f"{DEFAULT_REPORTS}"))
        if "auto_open"     in data: self._auto_open     = bool(data["auto_open"])
        if data.get("last_app_id"): self._last_app_id   = str(data["last_app_id"])
        if "wizard_seen"   in data: self._wizard_seen   = bool(data["wizard_seen"])
        stages = data.get("scan_stages")
        if isinstance(stages, dict):
            self._saved_scan_stages = {k: bool(v) for k, v in stages.items()
                                       if k in ("sca", "code", "dast", "api", "secrets")}
        paths = data.get("static_paths")
        if isinstance(paths, list):
            self._saved_static_paths = [str(p) for p in paths if isinstance(p, str) and p.strip()]
        if isinstance(data.get("dast_fields"), dict):
            self._saved_dast_fields = data["dast_fields"]
        if isinstance(data.get("api_fields"), dict):
            self._saved_api_fields = data["api_fields"]
        # Restore the global Probely API key. _load_settings() runs BEFORE
        # _build_vars(), so stash the raw value and apply it (var + shared store)
        # in _build_vars, the same deferred pattern used for dast_fields.
        pk = data.get("probely_key")
        if isinstance(pk, str) and pk.strip():
            self._saved_probely_key = pk.strip()

    def _save_settings(self):
        data = {"dark_mode": self._dark_mode, "reports_root": str(self._reports_root),
                "auto_open": self._auto_open,
                "last_app_id": getattr(self, "_last_app_id", None),
                "wizard_seen": getattr(self, "_wizard_seen", False)}
        # Global Probely (Snyk API & Web) API key — one per install, shared by
        # every app profile. Stored plain, like the other DAST fields.
        try:
            data["probely_key"] = self._probely_key_var.get().strip()
        except Exception:
            pass
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
        try:
            _SECRET = {"password", "token", "cookie", "header_value",
                       "selenium_pass_value", "login_data"}
            data["dast_fields"] = {
                "url":      self._dast_url_var.get(),
                "auth":     self._dast_auth_var.get(),
                "profile":  self._dast_profile_var.get(),
                "relogin":  bool(self._dast_relogin_var.get()),
                "browser":  self._dast_browser_var.get(),
                "headless": bool(self._dast_headless_var.get()),
                "selwait":  int(self._dast_selwait_var.get() or 15),
                "creds":    {k: v.get() for k, v in self._dast_cred_vars.items()
                             if k not in _SECRET},
                "probely": {
                    "region": self._dast_region_var.get(), "apibase": self._dast_apibase_var.get(),
                    "target_id": self._dast_target_id_var.get(), "reuse_url": bool(self._dast_reuse_url_var.get()),
                    "maxwait": int(self._dast_maxwait_var.get() or 180),
                    "reduced": self._dast_reduced_scopes_var.get(),
                    "blacklist": self._dast_blacklist_var.get(), "ignore_blackout": bool(self._dast_ignore_blackout_var.get()),
                    "report": self._dast_report_var.get(), "protect": bool(self._dast_protect_session_var.get()),
                    "agent_warn": bool(self._dast_agent_warn_var.get()), "seq_path": self._dast_seq_path_var.get(),
                    "form_login": self._dast_form_login_var.get(), "logout_cond": self._dast_logout_cond_var.get(),
                    "logout_url_det": bool(self._dast_logout_url_det_var.get()),
                    "logout_code_det": bool(self._dast_logout_code_det_var.get()),
                    "logout_selector": self._dast_logout_selector_var.get(),
                    "logout_body": self._dast_logout_body_var.get(), "logout_header": self._dast_logout_header_var.get(),
                    "twofa": bool(self._dast_2fa_var.get()), "otp_field": self._dast_otp_field_var.get(),
                    "otp_submit": self._dast_otp_submit_var.get(), "otp_alg": self._dast_otp_alg_var.get(),
                    "otp_digits": int(self._dast_otp_digits_var.get() or 6),
                    "orchestrate": bool(self._dast_orch_var.get()),
                    "cooldown": int(self._dast_cooldown_var.get() or 60),
                },
            }
        except Exception:
            pass
        try:
            data["api_fields"] = {
                "spec":    self._api_spec_var.get(),
                "base":    self._api_base_var.get(),
                "auth":    self._api_auth_var.get(),
                "profile": self._api_profile_var.get(),
                "tls":     bool(self._api_tls_var.get()),
                "proxy":   self._api_proxy_var.get(),
                "creds":   {k: v.get() for k, v in self._api_cred_vars.items()
                            if k not in _SECRET},
                "probely": {
                    "region": self._api_region_var.get(), "apibase": self._api_apibase_var.get(),
                    "target_id": self._api_target_id_var.get(), "reuse_url": bool(self._api_reuse_url_var.get()),
                    "maxwait": int(self._api_maxwait_var.get() or 180),
                    "reduced": self._api_reduced_scopes_var.get(),
                    "ignore_blackout": bool(self._api_ignore_blackout_var.get()),
                    "report": self._api_report_var.get(), "protect": bool(self._api_protect_session_var.get()),
                    "seq_path": self._api_seq_path_var.get(), "check_login": bool(self._api_check_login_var.get()),
                },
            }
        except Exception:
            pass
        try: SETTINGS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e: self._emit_log(f"[settings] could not save: {e}")
        if getattr(self, "_status_lbl", None) and self.winfo_exists():
            try: self._flash_saved()
            except Exception: pass

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

    def _session_snapshot(self, kind: str, selected: set) -> dict:
        sel = sorted(selected)
        needs_pw = (("dast" in sel and self._dast_auth_var.get() != "none") or
                    ("api"  in sel and self._api_auth_var.get()  != "none"))
        try:
            static_paths = [p for p in (getattr(self, "_static_paths_lb", None) and
                            self._static_paths_lb.get(0, "end") or [])
                            if p.strip() and not p.strip().startswith("(empty")]
        except Exception:
            static_paths = []
        _SECRET = {"password", "token", "cookie", "header_value",
                   "selenium_pass_value", "login_data"}
        dast_creds = {k: v.get() for k, v in self._dast_cred_vars.items()
                      if k not in _SECRET}
        dast = {
            "url": self._dast_url_var.get(), "auth": self._dast_auth_var.get(),
            "profile": self._dast_profile_var.get(),
            "relogin": bool(self._dast_relogin_var.get()),
            "browser": self._dast_browser_var.get(),
            "headless": bool(self._dast_headless_var.get()), "selwait": int(self._dast_selwait_var.get() or 15),
            "creds": dast_creds,
        }
        api_creds = {k: v.get() for k, v in self._api_cred_vars.items() if k not in _SECRET}
        api = {
            "spec": self._api_spec_var.get(), "base": self._api_base_var.get(),
            "auth": self._api_auth_var.get(), "profile": self._api_profile_var.get(),
            "tls": bool(self._api_tls_var.get()), "proxy": self._api_proxy_var.get(),
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
        try: SESSION_FILE.unlink(missing_ok=True)
        except Exception: pass
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
            "Cierre inesperado", msg,
            on_yes=lambda: self._resume_from_session(info),
            yes_label="  ▶  Sí, restaurar y ejecutar  " if not needs_pw else "  ↩  Restaurar config  ",
            no_label="  No, iniciar limpio  ")

    def _resume_from_session(self, info: dict):
        sel = set(info.get("selected") or [])
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
        try:
            if hasattr(self, "_static_paths_lb"):
                self._static_paths_lb.delete(0, "end")
                for p in info.get("static_paths", []):
                    self._static_paths_lb.insert("end", p)
        except Exception as e:
            self._emit_log(f"[session] static path list restore failed: {e!r}")
        d = info.get("dast") or {}
        try:
            self._dast_url_var.set(d.get("url", "https://"))
            _auth = d.get("auth", "none")
            self._dast_auth_var.set("none" if _auth == "auto" else _auth)
            self._dast_profile_var.set({"passive": "(predeterminado)", "active": "full"}.get(
                d.get("profile", "(predeterminado)"), d.get("profile", "(predeterminado)")))
            self._dast_relogin_var.set(bool(d.get("relogin", True)))
            self._dast_browser_var.set(d.get("browser", "chrome"))
            self._dast_headless_var.set(bool(d.get("headless", True))); self._dast_selwait_var.set(int(d.get("selwait", 15)))
            for k, v in (d.get("creds") or {}).items():
                if k in self._dast_cred_vars: self._dast_cred_vars[k].set(v)
        except Exception as e:
            self._emit_log(f"[session] DAST restore partial: {e!r}")
        a = info.get("api") or {}
        try:
            self._api_spec_var.set(a.get("spec", "")); self._api_base_var.set(a.get("base", ""))
            self._api_auth_var.set(a.get("auth", "none")); self._api_profile_var.set(
                {"passive": "(predeterminado)", "active": "full"}.get(
                    a.get("profile", "(predeterminado)"), a.get("profile", "(predeterminado)")))
            self._api_tls_var.set(bool(a.get("tls", True)))
            self._api_proxy_var.set(a.get("proxy", ""))
            for k, v in (a.get("creds") or {}).items():
                if k in self._api_cred_vars: self._api_cred_vars[k].set(v)
        except Exception as e:
            self._emit_log(f"[session] API restore partial: {e!r}")
        try: self._refresh_scan_btn()
        except Exception: pass
        try: self._save_settings()
        except Exception: pass

        if info.get("needs_password"):
            tab = "dast" if ("dast" in sel and (info.get("dast") or {}).get("auth","none") != "none") else "api"
            try: self._show_tab(tab)
            except Exception: pass
            try:
                if tab == "dast": self._refresh_dast_creds()
            except Exception: pass
            self._show_info_popup(
                "Restaurado — se requiere contraseña",
                "I restored the previous scan's configuration.\n\n"
                f"Since it includes {tab.upper()} with authentication, re-enter "
                "the password/token in the credentials fields, then press "
                "▶ Run to start the scan.")
            return

        self._emit_log("[session] resuming previous scan with restored config…")
        kind = info.get("kind")
        attempts = [0]
        def _kick_off():
            if getattr(self, "_busy", False) and attempts[0] < 75:
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
                            yes_label="  Sí  ", no_label="  No  "):
        popup = self._create_popup(title)
        self._popup_hdr(popup, title, icon="⚠")
        self._centered_msg(popup, "⚠", T["accent"], title, message, T["text"])
        def _yes():
            popup.close()
            try: on_yes()
            except Exception as e: self._emit_log(f"[session] resume failed: {e!r}")
        self._popup_foot(popup, (no_label, popup.close, "flat"), (yes_label, _yes, "accent"))

    def _apply_theme_to_app(self):
        _apply_palette(self._dark_mode)
        self._setup_styles()
        self._recolour_widget(self)
        self._recolour_ribbon_tabs()
        try: self._refresh_stage_cards()
        except Exception: pass
        for key, pill in getattr(self, "_stage_pills", {}).items():
            try:
                if pill.cget("text") == "● EN ESPERA":
                    pill.configure(bg=T["pill_idle_bg"], fg=T["pill_idle_fg"])
            except Exception: pass
        for _attr in ("_static_sca_tree", "_static_sast_tree"):
            _t = getattr(self, _attr, None)
            if _t is not None:
                try: self._apply_group_tags(_t)
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
                    btn.config(bg=T["surface2"], fg=T["accent"],
                               activebackground=T["card_hover"], activeforeground=T["accent"])
                else:
                    btn.config(bg=T["panel_bg"], fg=T["muted"],
                               activebackground=T["card_hover"], activeforeground=T["accent"])
            except Exception: pass
        for attr in ("_app_chip_frame", "_app_chip_lbl", "_app_chip_counts"):
            w = getattr(self, attr, None)
            if w:
                try: w.config(bg=T["surface2"])
                except Exception: pass
        auth_frame = getattr(self, "_auth_badge_frame", None)
        if auth_frame:
            try: auth_frame.config(bg=T["surface2"], highlightbackground=T["border"])
            except Exception: pass
        auth_lbl = getattr(self, "_auth_badge_lbl", None)
        if auth_lbl:
            try: auth_lbl.config(bg=T["surface2"])
            except Exception: pass
        theme_btn = getattr(self, "_theme_ribbon_btn", None)
        if theme_btn:
            try: theme_btn.config(bg=T["panel_bg"], fg=T["muted"],
                                   activebackground=T["card_hover"])
            except Exception: pass
        wizard_btn = getattr(self, "_wizard_ribbon_btn", None)
        if wizard_btn:
            try: wizard_btn.config(bg=T["accent"], fg=T["button_fg"],
                                    activebackground=T["accent_hi"],
                                    activeforeground=T["button_fg"])
            except Exception: pass
        run_wrap = getattr(self, "_run_icon_wrap", None)
        if run_wrap:
            try:
                run_wrap.configure(bg=T["accent"])
                run_btn = getattr(self, "_run_icon_btn", None)
                if run_btn: run_btn.configure(fg=T["accent"])
            except Exception: pass
        try: self._update_key_icon_style()
        except Exception: pass
        try: self._update_probely_badge_style()
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
            return k in ("sca", "code")
        self._scan_vars = {k: tk.BooleanVar(value=_stage_default(k))
                           for k in ("sca", "code", "dast", "api", "secrets")}
        self._dast_url_var = tk.StringVar(value="https://")
        self._dast_auth_var = tk.StringVar(value="selenium")
        self._dast_profile_var = tk.StringVar(value="(predeterminado)")
        self._dast_relogin_var = tk.BooleanVar(value=True)
        self._dast_browser_var = tk.StringVar(value="chrome")
        self._dast_browser_label_var = tk.StringVar(value="Google Chrome")
        self._browser_catalog = {}
        self._browser_label_key = {}
        self._dast_headless_var = tk.BooleanVar(value=True)
        self._dast_selwait_var = tk.IntVar(value=15)
        self._dast_cred_vars = {k: tk.StringVar() for k in self._CRED_KEYS}
        self._dast_region_var = tk.StringVar(value="us")
        self._dast_apibase_var = tk.StringVar(value="")
        self._dast_target_id_var = tk.StringVar(value="")
        self._dast_reuse_url_var = tk.BooleanVar(value=True)
        self._dast_maxwait_var = tk.IntVar(value=180)
        self._dast_poll_var = tk.IntVar(value=15)
        self._dast_require_verified_var = tk.BooleanVar(value=False)
        self._dast_reduced_scopes_var = tk.StringVar(value="")
        self._dast_extra_hosts_var = tk.StringVar(value="")
        self._dast_blacklist_var = tk.StringVar(value="")
        self._dast_ignore_blackout_var = tk.BooleanVar(value=False)
        self._dast_report_var = tk.StringVar(value="(ninguno)")
        self._dast_protect_session_var = tk.BooleanVar(value=True)
        self._dast_agent_warn_var = tk.BooleanVar(value=True)
        self._dast_seq_path_var = tk.StringVar(value="")
        self._dast_form_login_var = tk.StringVar(value="auto")
        self._dast_logout_cond_var = tk.StringVar(value="any")
        self._dast_logout_url_det_var = tk.BooleanVar(value=True)
        self._dast_logout_code_det_var = tk.BooleanVar(value=True)
        self._dast_logout_selector_var = tk.StringVar(value="")
        self._dast_logout_body_var = tk.StringVar(value="")
        self._dast_logout_header_var = tk.StringVar(value="")
        self._dast_2fa_var = tk.BooleanVar(value=False)
        self._dast_otp_secret_var = tk.StringVar(value="")
        self._dast_otp_field_var = tk.StringVar(value="")
        self._dast_otp_submit_var = tk.StringVar(value="")
        self._dast_otp_alg_var = tk.StringVar(value="SHA1")
        self._dast_otp_digits_var = tk.IntVar(value=6)
        # ── Slot-pool orchestrator (Probely targets) ────────────────────────────
        # Pool size is fixed at 5 (licence cap) — not user-configurable. Region is
        # hardcoded to US. Only the auto-orchestrate toggle and the per-slot
        # cooldown are exposed.
        self._dast_orch_var = tk.BooleanVar(value=True)
        self._dast_cooldown_var = tk.IntVar(value=60)
        self._api_spec_var = tk.StringVar(value="")
        self._api_base_var = tk.StringVar(value="")
        self._api_auth_var = tk.StringVar(value="none")
        self._api_profile_var = tk.StringVar(value="(predeterminado)")
        self._api_tls_var = tk.BooleanVar(value=True)
        self._api_proxy_var = tk.StringVar(value="")
        self._api_cred_vars = {k: tk.StringVar() for k in
                               ("username", "password", "token", "cookie", "header_name",
                                "header_value")}
        self._api_region_var = tk.StringVar(value="us")
        self._api_apibase_var = tk.StringVar(value="")
        self._api_target_id_var = tk.StringVar(value="")
        self._api_reuse_url_var = tk.BooleanVar(value=True)
        self._api_maxwait_var = tk.IntVar(value=180)
        self._api_reduced_scopes_var = tk.StringVar(value="")
        self._api_ignore_blackout_var = tk.BooleanVar(value=False)
        self._api_report_var = tk.StringVar(value="(ninguno)")
        self._api_protect_session_var = tk.BooleanVar(value=True)
        self._api_seq_path_var = tk.StringVar(value="")
        self._api_check_login_var = tk.BooleanVar(value=True)
        self._api_require_verified_var = tk.BooleanVar(value=False)
        self._api_schema_type_var = tk.StringVar(value="(auto)")
        self._api_login_url_var = tk.StringVar(value="")
        self._api_login_payload_var = tk.StringVar(value="")
        self._api_login_media_var = tk.StringVar(value="application/json")
        self._api_login_token_field_var = tk.StringVar(value="")
        self._api_login_token_param_var = tk.StringVar(value="Authorization")
        self._api_login_token_prefix_var = tk.StringVar(value="")
        self._api_login_place_var = tk.StringVar(value="header")
        # ── Probely (Snyk API & Web) API key — GLOBAL, one per install ──────────
        # Separate from the Snyk SSO token. The user pastes a key issued by the
        # Cybersecurity team (request via slunam@bancobase.com); it is shared by
        # every app profile and used by both the DAST and API cloud stages.
        self._probely_key_var = tk.StringVar(value="")
        # Auth badge state for Probely, mirroring _key_auth_status for Snyk:
        # "unauth" (no/invalid key), "checking" (validating), "auth" (validated).
        self._probely_auth_status = "unauth"
        # Apply any key restored from settings (stashed in _load_settings, which
        # runs before this point), then keep the shared static_scanner store in
        # sync with the var so every DastConfig/ApiConfig sees the current key.
        _saved_pk = getattr(self, "_saved_probely_key", "")
        if _saved_pk:
            self._probely_key_var.set(_saved_pk)
        try:
            set_probely_key(self._probely_key_var.get().strip())
        except Exception:
            pass

        def _on_probely_key_change(*_):
            try:
                set_probely_key(self._probely_key_var.get().strip())
            except Exception:
                pass
            # A changed key is unvalidated until checked again.
            self._set_probely_status("unauth")
        try:
            self._probely_key_var.trace_add("write", _on_probely_key_change)
        except Exception:
            pass
        self._status_var = tk.StringVar(value='Inicializando…')
        self._stage_pills: dict[str, tk.Label] = {}
        self._stage_apply: dict[str, Callable[[bool], None]] = {}
        self._stage_bar_update: dict[str, object] = {}
        self._pipe_stage_states: dict[str, str] = {}
        self._pipe_card_pcts: dict[str, float] = {}
        self._pipe_progress_pct: float = 0.0
        self._recent_paths: list[Path] = []
        self._restore_dast_fields()
        self._restore_api_fields()

    def _build_ui(self):
        self._build_ribbon(); self._build_body(); self._build_status_bar(); self._show_tab("scan")

    def _build_ribbon(self):
        self._ribbon = tk.Frame(self, bg=T["panel_bg"])
        self._ribbon.pack(side="top", fill="x")

        top_row = tk.Frame(self._ribbon, bg=T["panel_bg"])
        top_row.pack(fill="x", side="top")
        tk.Frame(self._ribbon, bg=T["accent"], height=2).pack(fill="x", side="top", before=top_row)

        brand_frame = tk.Frame(top_row, bg=T["panel_bg"])
        brand_frame.pack(side="left", padx=(12, 0), pady=5)
        brand_box = tk.Frame(brand_frame, bg=T["accent"], padx=5, pady=3)
        brand_box.pack(side="left")
        tk.Label(brand_box, text="⬡", font=(_FUI, 12, "bold"),
                 bg=T["accent"], fg=T["button_fg"]).pack()
        tk.Label(brand_frame, text="  SecDevOps · Banco Base",
                 font=(_FUI, 11, "bold"), bg=T["panel_bg"], fg=T["text"],
                 anchor="w").pack(side="left")

        tk.Frame(top_row, bg=T["border_bg"], width=1).pack(side="left", fill="y", padx=(12, 0), pady=6)

        self._app_chip_frame = tk.Frame(top_row, bg=T["surface2"],
                                        highlightthickness=1, highlightbackground=T["border"],
                                        cursor="hand2")
        self._app_chip_frame.pack(side="left", padx=12, pady=7)
        self._app_chip_frame.bind("<Button-1>", lambda e: self._show_tab("apps"))
        self._app_chip_dot = tk.Frame(self._app_chip_frame, bg=T["accent"],
                                      width=7, height=7)
        self._app_chip_dot.pack(side="left", padx=(8, 4), pady=8)
        self._app_chip_dot.bind("<Button-1>", lambda e: self._show_tab("apps"))
        self._app_chip_lbl = tk.Label(self._app_chip_frame,
                                      text="Sin aplicación — haga clic para seleccionar",
                                      font=(_FUI, 10, "bold"), bg=T["surface2"], fg=T["muted"],
                                      cursor="hand2")
        self._app_chip_lbl.pack(side="left", padx=(0, 4), pady=6)
        self._app_chip_lbl.bind("<Button-1>", lambda e: self._show_tab("apps"))
        self._app_chip_counts = tk.Label(self._app_chip_frame, text="",
                                         font=(_FUI, 9), bg=T["surface2"], fg=T["muted"],
                                         cursor="hand2")
        self._app_chip_counts.pack(side="left", padx=(2, 8), pady=6)
        self._app_chip_counts.bind("<Button-1>", lambda e: self._show_tab("apps"))

        right = tk.Frame(top_row, bg=T["panel_bg"])
        right.pack(side="right", padx=10, pady=5)

        _auth_wrap = tk.Frame(right, bg=T["border"], padx=2, pady=2)
        _auth_wrap.pack(side="left", padx=(0, 8))
        self._auth_badge_lbl = tk.Button(_auth_wrap, text="🔑",
                                         font=(_FUI, 13, "bold"),
                                         command=self._show_auth_status_popup,
                                         bg=T["panel_bg"], fg=T["muted"],
                                         activebackground=T["surface2"],
                                         activeforeground=T["muted"],
                                         relief="flat", bd=0, padx=9, pady=5,
                                         cursor="hand2")
        self._auth_badge_lbl.pack(fill="both", expand=True)
        self._auth_badge_frame = _auth_wrap
        self._key_icon_btn  = self._auth_badge_lbl
        self._key_icon_wrap = self._auth_badge_frame

        # Probely (Snyk API & Web) key badge — same visual language as 🔑, but
        # for the per-user cloud-scan API key. Optional: greyed until a stage
        # that needs it is selected or a key is pasted.
        _probely_wrap = tk.Frame(right, bg=T["border"], padx=2, pady=2)
        _probely_wrap.pack(side="left", padx=(0, 8))
        self._probely_badge_lbl = tk.Button(_probely_wrap, text="🌐",
                                            font=(_FUI, 13, "bold"),
                                            command=self._show_probely_key_popup,
                                            bg=T["panel_bg"], fg=T["muted"],
                                            activebackground=T["surface2"],
                                            activeforeground=T["muted"],
                                            relief="flat", bd=0, padx=9, pady=5,
                                            cursor="hand2")
        self._probely_badge_lbl.pack(fill="both", expand=True)
        self._probely_badge_frame = _probely_wrap

        _run_wrap = tk.Frame(right, bg=T["accent"], padx=2, pady=2)
        _run_wrap.pack(side="left", padx=(0, 4))
        self._run_icon_btn = tk.Button(_run_wrap, text="▶",
                                       font=(_FUI, 13, "bold"),
                                       command=self._start_scan,
                                       bg=T["panel_bg"], fg=T["accent"],
                                       activebackground=T["surface2"],
                                       activeforeground=T["accent"],
                                       relief="flat", bd=0, padx=9, pady=5,
                                       cursor="hand2",
                                       disabledforeground=T["muted"],
                                       state="disabled")
        self._run_icon_btn.pack(fill="both", expand=True)
        self._run_icon_wrap = _run_wrap

        _stop_wrap = tk.Frame(right, bg=T["muted"], padx=2, pady=2)
        _stop_wrap.pack(side="left", padx=(0, 4))
        self._stop_icon_btn = tk.Button(_stop_wrap, text="■",
                                        font=(_FUI, 13, "bold"),
                                        command=self._request_cancel,
                                        bg=T["panel_bg"], fg=T["muted"],
                                        activebackground=T["surface2"],
                                        activeforeground=T["err"],
                                        relief="flat", bd=0, padx=9, pady=5,
                                        cursor="hand2",
                                        disabledforeground=T["muted"],
                                        state="disabled")
        self._stop_icon_btn.pack(fill="both", expand=True)
        self._stop_icon_wrap = _stop_wrap

        self._theme_ribbon_btn = tk.Button(right,
                                           text="🌙" if self._dark_mode else "☀",
                                           font=(_FUI, 13),
                                           command=self._toggle_theme,
                                           bg=T["panel_bg"], fg=T["muted"],
                                           activebackground=T["card_hover"],
                                           relief="flat", bd=0, padx=6, pady=4,
                                           cursor="hand2")
        self._theme_ribbon_btn.pack(side="left", padx=(4, 0))

        tk.Frame(self._ribbon, bg=T["border_bg"], height=1).pack(fill="x")

        tab_row = tk.Frame(self._ribbon, bg=T["panel_bg"])
        tab_row.pack(fill="x", side="top")

        self._ribbon_tabs: dict[str, tk.Button] = {}
        tabs = [
            ("scan",    "▶  Ejecutar escaneo"),
            ("static",  "⌨  Análisis de código"),
            ("dast",    "🌐  Pruebas web"),
            ("api",     "⬡  Seguridad de API"),
            ("reports", "📋  Reportes"),
            ("apps",    "📦  Aplicaciones"),
        ]
        for key, label in tabs:
            btn = tk.Button(tab_row, text=label,
                            command=lambda k=key: self._show_tab(k),
                            bg=T["panel_bg"], fg=T["muted"],
                            font=(_FUI, 10, "bold"), relief="flat", bd=0,
                            padx=14, pady=8, cursor="hand2",
                            activebackground=T["card_hover"],
                            activeforeground=T["accent"])
            btn.pack(side="left")
            self._ribbon_tabs[key] = btn

        tk.Frame(tab_row, bg=T["border_bg"], width=1).pack(side="right", fill="y", pady=4, padx=4)
        self._wizard_ribbon_btn = self._btn(
            tab_row, "🧙  Asistente", self.open_wizard, "accent")
        self._wizard_ribbon_btn.pack(side="right")

        tk.Frame(self._ribbon, bg=T["accent"], height=2).pack(fill="x", side="bottom")

        self._set_key_status("checking")

    def _show_tab(self, key: str):
        self._active_tab = key
        for k, btn in self._ribbon_tabs.items():
            if k == key:
                btn.config(bg=T["panel_bg"], fg=T["accent"],
                           activebackground=T["card_hover"],
                           activeforeground=T["accent"],
                           relief="flat")
                btn.config(highlightthickness=0)
                btn.config(bg=T["surface2"])
            else:
                btn.config(bg=T["panel_bg"], fg=T["muted"],
                           activebackground=T["card_hover"],
                           activeforeground=T["accent"],
                           highlightthickness=0)
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
        self._console_btn = tk.Button(bar, text="▥  Consola", command=self._toggle_console,
                                      font=self.fonts["caption"], bg=T["panel_bg"], fg=T["muted"], relief="flat",
                                      padx=8, pady=0, cursor="hand2", activebackground=T["card_hover"])
        self._console_btn.pack(side="left", padx=8)
        os_tag = "macOS" if IS_MAC else ("Windows" if IS_WIN else "Linux")
        user_box = tk.Frame(bar, bg=T["panel_bg"]); user_box.pack(side="right", padx=10)
        tk.Label(user_box, text=f"  ·  {os_tag}", font=self.fonts["caption"], bg=T["panel_bg"], fg=T["muted"]).pack(side="right")
        tk.Label(user_box, text=f"👤 {self._user}", font=self.fonts["caption"], bg=T["panel_bg"], fg=T["text"]).pack(side="right")
        self._progress_box = tk.Frame(bar, bg=T["panel_bg"])
        self._progress_lbl = tk.Label(self._progress_box, text="", font=self.fonts["caption"],
                                      bg=T["panel_bg"], fg=T["muted"])
        self._progress_lbl.pack(side="left", padx=(0, 6))
        self._progress_bar = ttk.Progressbar(self._progress_box, mode="determinate",
                                             length=140, maximum=100)
        self._progress_bar.pack(side="left")
        self._status_lbl = tk.Label(bar, textvariable=self._status_var, font=self.fonts["caption"],
                                    bg=T["panel_bg"], fg=T["accent"], anchor="center")
        self._status_lbl.pack(expand=True)
        self._flash_after: Optional[str] = None

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
        icon = "🌙" if self._dark_mode else "☀"
        try: self._theme_btn.configure(text=icon)
        except Exception: pass
        try: self._theme_ribbon_btn.configure(text=icon)
        except Exception: pass


    def _build_console(self, parent):
        hdr = tk.Frame(parent, bg=T["accent"], padx=10, pady=6); hdr.pack(fill="x")
        tk.Label(hdr, text="REGISTRO DE ACTIVIDAD", font=(_FUI, 11, "bold"), bg=T["accent"], fg=T["button_fg"]).pack(side="left")
        _themed_btn(hdr, "✕ Cerrar", self._toggle_console, font=self.fonts["small"], bg=T["accent"],
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
        self._console_btn.configure(text="▥  Consola", fg=T["text"])

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

    def _card_header(self, outer: tk.Frame, title: str, *, pad: int = 14) -> tk.Frame:
        """Shared header chrome for _card/_panel/_side_card: a left accent
        stripe + bottom hairline on a white header, instead of a solid
        accent block. The block, repeated on every single card across
        every tab, was the single biggest source of visual noise in the
        old theme — the accent colour now only fires on the things that
        actually need attention (primary buttons, the active-app banner,
        status pills). Returns the header row so _panel can still pack a
        right-aligned live summary into it."""
        wrap = tk.Frame(outer, bg=T["panel_bg"]); wrap.pack(fill="x", side="top")
        tk.Frame(wrap, bg=T["accent"], width=3).pack(side="left", fill="y")
        hdr = tk.Frame(wrap, bg=T["panel_bg"], padx=max(pad - 3, 6), pady=8)
        hdr.pack(side="left", fill="x", expand=True)
        tk.Label(hdr, text=title, font=(_FUI, 10, "bold"), bg=T["panel_bg"], fg=T["text"], anchor="w").pack(side="left")
        tk.Frame(outer, bg=T["border_bg"], height=1).pack(fill="x", side="top")
        return hdr

    def _card(self, parent, title="", *, pady=(0, 10)) -> tk.Frame:
        outer = tk.Frame(parent, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        outer.pack(fill="x", pady=pady)
        if title:
            self._card_header(outer, title)
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

    def _panel(self, parent, title, *, pady=(0, 10)):
        """Like _card but returns (inner_body, header_right) so callers can drop a
        live summary on the right of the header. Same brand chrome as _card."""
        outer = tk.Frame(parent, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        outer.pack(fill="x", pady=pady)
        hdr = self._card_header(outer, title)
        right = tk.Frame(hdr, bg=T["panel_bg"]); right.pack(side="right")
        inner = tk.Frame(outer, bg=T["panel_bg"], padx=14, pady=10); inner.pack(fill="both", expand=True)
        return inner, right


    def _side_card(self, row, title, *, padx=(0, 0), pad=14, ipady=10) -> tk.Frame:
        outer = tk.Frame(row, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        outer.pack(side="left", fill="both", expand=True, padx=padx)
        self._card_header(outer, title, pad=pad)
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
            if "relief" not in cfg: cfg["relief"] = "flat"
            return tk.Button(parent, text=text, command=cmd, cursor="hand2", bd=0, **cfg, **kw)

        if kind == "accent":
            return tk.Button(parent, text=text, command=cmd, bg=T["accent"], fg=T["button_fg"],
                             activebackground=T["accent_hi"], activeforeground=T["button_fg"],
                             font=_base_font, padx=_base_pad[0], pady=_base_pad[1],
                             cursor="hand2", bd=0, relief="flat", **kw)
        if kind == "danger":
            return tk.Button(parent, text=text, command=cmd, bg=T["accent2"], fg=T["button_fg"],
                             activebackground=T["accent2_hi"], activeforeground=T["button_fg"],
                             font=_base_font, padx=_base_pad[0], pady=_base_pad[1],
                             cursor="hand2", bd=0, relief="flat", **kw)
        if kind == "flat":
            return tk.Button(parent, text=text, command=cmd, bg=T["panel_bg"], fg=T["muted"],
                             activebackground=T["surface2"], activeforeground=T["text"],
                             font=(_FUI, 11), padx=10, pady=5,
                             cursor="hand2", bd=0, relief="flat", **kw)
        container = tk.Frame(parent, bg=T["border_bg"])
        inner_btn = tk.Button(container, text=text, command=cmd, bg=T["panel_bg"], fg=T["text"],
                              activebackground=T["surface2"], activeforeground=T["text"],
                              font=_base_font, padx=_base_pad[0], pady=_base_pad[1],
                              cursor="hand2", bd=0, relief="flat", **kw)
        inner_btn.pack(fill="both", expand=True, padx=1, pady=1)
        inner_btn.pack = lambda *a, **kwa: container.pack(*a, **kwa)
        inner_btn.grid = lambda *a, **kwa: container.grid(*a, **kwa)
        inner_btn.container = container
        return inner_btn

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
        f = tk.Frame(parent, bg=T["border_bg"], height=1); f.pack(fill="x", **pk)
        return f

    def _create_popup(self, title: str = "Window", w_pct: float = 0.75, h_pct: float = 0.75,
                      on_escape=None) -> tk.Frame:
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

        _esc_handler = on_escape if on_escape is not None else _close
        win.bind("<Escape>", lambda e: _esc_handler(), add="+")
        _bind_ids.update(_popup_follow_parent(win, self))
        content = _apply_panel_chrome(win)
        content.close = _close   # type: ignore[attr-defined]
        content._win = win       # type: ignore[attr-defined]
        return content

    def _popup_hdr(self, popup: tk.Frame, title: str, subtitle: str = "", icon: str = "",
                   on_close=None) -> tk.Frame:
        """Standard popup header: panel_bg band with title (in accent), optional icon/subtitle,
        and a close ✕ on the right.

        on_close — if provided, the ✕ button calls this instead of popup.close().
                   The wizard passes its confirm-before-close handler here.
        hdr._row — exposed so callers can pack extra widgets (e.g. a step counter)
                   into the same row without duplicating the chrome.
        """
        bg = T["panel_bg"]
        hdr = tk.Frame(popup, bg=bg, padx=30, pady=16); hdr.pack(fill="x")
        row = tk.Frame(hdr, bg=bg); row.pack(fill="x")
        tk.Label(row, text=f"{icon}  {title}" if icon else title, font=(_FUI, 15, "bold"),
                 bg=bg, fg=T["accent"]).pack(side="left")
        if subtitle:
            tk.Label(row, text=subtitle, font=(_FUI, 11, "italic"), bg=bg, fg=T["muted"]).pack(side="left", padx=(12, 0))
        _close_fn = on_close or getattr(popup, "close", None)
        if _close_fn:
            xbtn = tk.Label(row, text="✕", font=(_FUI, 13, "bold"), bg=bg, fg=T["muted"], cursor="hand2", padx=6)
            xbtn.pack(side="right")
            xbtn.bind("<Button-1>", lambda e: _close_fn())
            xbtn.bind("<Enter>", lambda e: xbtn.config(fg=T["err"]))
            xbtn.bind("<Leave>", lambda e: xbtn.config(fg=T["muted"]))
        hdr._row = row
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
        tk.Frame(row, bg=T["border_bg"], width=1).pack(side="left", fill="y", padx=(0, 40))
        txt = tk.Frame(row, bg=bg); txt.pack(side="left", fill="x", expand=True)
        tk.Label(txt, text=title, font=(_FUI, 20, "bold"), bg=bg, fg=T["text"], anchor="w").pack(anchor="w")
        tk.Frame(txt, bg=T["border_bg"], height=1).pack(fill="x", pady=(10, 12))
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
        self._popup_foot(popup, ("  Aceptar  ", popup.close, "accent"))

    def _show_info_popup(self, title, message):  self._show_popup(title, message, "info")
    def _show_warn_popup(self, title, message):  self._show_popup(title, message, "warn")
    def _show_error_popup(self, title, message): self._show_popup(title, message, "error")

    def _show_probely_verify_popup(self, stage: str, evidence: str):
        """Surface a Probely domain-verification block with the token + the
        verification methods Snyk API & Web supports, so the user can unblock the
        scan instead of just seeing a buried 'high' finding."""
        token = ""
        m = _re.search(r"verification token:\s*([^\s).]+)", evidence or "", _re.I)
        if m:
            token = m.group(1).strip()
        msg = (
            f"El dominio del objetivo {stage.upper()} NO está verificado en Snyk API & Web.\n"
            "Probely solo permite escaneos 'lightning' (o ninguno) hasta verificar el dominio.\n\n"
            + (f"Token de verificación:\n{token}\n\n" if token else "")
            + "Métodos de verificación disponibles:\n"
            "  · dns_txt — registro TXT en el DNS del dominio\n"
            "  · dns_cname — registro CNAME en el DNS\n"
            "  · meta_tag — etiqueta <meta> en la página índice\n"
            "  · file — archivo de texto en la raíz del sitio\n"
            "  · email / aws_route53 / cloudflare — verificación automática\n\n"
            "Verifica el dominio en el panel de Probely (plus.us.probely.app, según tu región) y reintenta el escaneo."
        )
        self._show_info_popup("Verificación de dominio requerida (Probely)", msg)


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
        try:
            if IS_WIN:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(os.getpid())],
                               capture_output=True)
            else:
                os.killpg(os.getpgid(os.getpid()), 9)
        except Exception:
            os._exit(0)

    def _maybe_open_wizard_on_first_launch(self) -> None:
        """Open the guided setup wizard automatically on first ever launch.
        Skipped on subsequent launches (wizard_seen persisted to settings).
        Also skipped if a crash-recovery resume is already in progress — the
        session restore handles its own flow and we don't want to interrupt it."""
        if getattr(self, "_wizard_seen", False):
            return
        if SESSION_FILE.exists():
            return
        self._wizard_seen = True
        self._save_settings()
        self.open_wizard()


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
            self._log_line(f"[ocupado] ignorando '{label}' — otra operación en progreso"); return
        setattr(self, busy_attr, True)
        self._update_stop_btn_style(); self._set_status(f"Ejecutando: {label}…")
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
                    result = payload
                    if result is not None:
                        if getattr(result, "ok", False):
                            self._log_line("[auth] autenticado.")
                            if self._auth_proc is not None:
                                _kill_process_tree(self._auth_proc)
                                self._auth_proc = None
                            _close_fn = getattr(self, "_login_popup_close", None)
                            if callable(_close_fn):
                                _close_fn()
                        self._apply_checks({"auth": result})
                    else:
                        self._set_key_status("unauth")
                    if not self._any_busy():
                        self._set_status('✔  Listo')
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
                        _pill_labels = {"running": "● EJECUTANDO", "done": "● OK", "failed": "● ERROR", "skipped": "● OMITIDO"}
                        pill.config(text=_pill_labels.get(label, f"● {label.upper()[:4]}"), bg=bg, fg=fg)
                    try:
                        self._update_pipeline_progress(key, label)
                    except Exception:
                        pass
                elif kind == "pipeline_reset":
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
                elif kind == "card_progress":
                    stage_key, done, total = payload
                    try:
                        self._update_card_progress(stage_key, done, total)
                    except Exception:
                        pass
                elif kind == "progress":
                    label, done, total = payload
                    if label in ("DAST", "API"):
                        self._show_progress(label, done, total)
                elif kind == "auth_required":
                    self._prompt_relogin()
                elif kind == "probely_required":
                    # A cloud stage needs Probely but no valid key is present.
                    self._set_probely_status("unauth")
                    try: self._refresh_probely_banner()
                    except Exception: pass
                elif kind == "probely_ok":
                    self._set_probely_status("auth")
                elif kind == "probely_validated":
                    try:
                        _ok, _msg, _cb = payload
                    except Exception:
                        _ok, _msg, _cb = (False, str(payload), None)
                    self._set_probely_status("auth" if _ok else "unauth")
                    self._emit_log(f"[snyk-aw] {'✓' if _ok else '✕'} {_msg}")
                    if callable(_cb):
                        try: _cb(_ok, _msg)
                        except Exception: pass
                elif kind == "probely_verify":
                    try:
                        _stage_k, _ev = payload
                    except Exception:
                        _stage_k, _ev = ("", str(payload))
                    self._show_probely_verify_popup(_stage_k, _ev)
                elif kind == "report":
                    self._last_report = Path(payload)
                    self._open_btn.config(state="normal"); self._csv_btn.config(state="normal")
                    self._refresh_recent(); self._refresh_rep_tree()
                    self._refresh_active_app_banner()
                    if self._auto_open: _open_path(self._last_report)
                elif kind == "scan_profiles":
                    which, profs = payload
                    cb = getattr(self, "_api_profile_cb" if which == "api"
                                 else "_dast_profile_cb", None)
                    if cb is not None and profs:
                        cb.config(values=["(predeterminado)"] + [p[0] for p in profs])
                        self._emit_log(f"[{which}] {len(profs)} perfil(es) de escaneo de Probely cargados")
                    else:
                        self._emit_log(f"[{which}] no se pudieron cargar perfiles — se mantiene la lista estática")
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
                            self._static_count_lbl.config(text="Escaneo fallido — vea la consola.")
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
                        self._set_status('✔  Listo'); self._hide_progress()
                        try:
                            self._pipe_progress_pct = getattr(self, "_pipe_progress_pct", 0.0)
                        except Exception:
                            pass
                elif kind == "__static_done__":
                    self._static_busy = False; self._update_stop_btn_style()
                    if not self._any_busy():
                        self._set_status('✔  Listo'); self._hide_progress()
                elif kind == "__orch_done__":
                    self._orch_busy = False
                    if not self._any_busy():
                        self._set_status('✔  Listo')
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
            self._console_btn.configure(text=f"▥  Consola ({self._unread_log})", fg=T["err"])

    def _any_busy(self) -> bool:
        """True while either independent lane (main pipeline or Static-tab
        quick scan) is running. Used anywhere that needs 'is it safe to do
        X right now' rather than 'is this one specific lane running' —
        the Stop button, the dependency reinstaller, and the idle/'Ready.'
        reset all care about *either* lane, not just the pipeline's."""
        return bool(self._busy) or bool(getattr(self, "_static_busy", False))

    def _update_key_icon_style(self):
        """Paint the auth badge in the ribbon top row from self._key_auth_status."""
        status = getattr(self, "_key_auth_status", "checking")
        badge_frame = getattr(self, "_auth_badge_frame", None)
        badge_lbl   = getattr(self, "_auth_badge_lbl", None)
        if badge_frame and badge_lbl:
            if status == "auth":
                fg   = T["ok"]
                hbdr = T["ok"]
            elif status == "unauth":
                fg   = T["err"]
                hbdr = T["err"]
            else:
                fg   = T["muted"]
                hbdr = T["border"]
            try:
                badge_frame.configure(bg=hbdr)
                badge_lbl.configure(fg=fg, bg=T["panel_bg"], activeforeground=fg)
            except Exception:
                pass
        btn  = getattr(self, "_key_icon_btn", None)
        wrap = getattr(self, "_key_icon_wrap", None)
        if btn and btn is not badge_lbl:
            colour = {"unauth": T["err"], "checking": T["muted"], "auth": T["ok"]}.get(status, T["muted"])
            if wrap:
                try: wrap.configure(bg=colour)
                except Exception: pass
            try: btn.configure(fg=colour, activeforeground=colour,
                               activebackground=T["card_hover"], bg=T["panel_bg"])
            except Exception: pass

    def _set_key_status(self, status: str):
        """status: 'unauth' (red), 'checking' (gray), 'auth' (green)."""
        self._key_auth_status = status
        self._update_key_icon_style()

    # ── Probely (Snyk API & Web) key badge + validation ──────────────────────
    def _probely_configured(self) -> bool:
        """True if a non-empty Probely API key is present (NOT necessarily
        validated). Used to decide whether the cloud DAST/API stages can run."""
        try:
            return bool(self._probely_key_var.get().strip())
        except Exception:
            return False

    def _update_probely_badge_style(self):
        """Paint the 🌐 Probely badge in the ribbon from _probely_auth_status,
        mirroring the 🔑 Snyk badge styling exactly."""
        status = getattr(self, "_probely_auth_status", "unauth")
        wrap = getattr(self, "_probely_badge_frame", None)
        btn  = getattr(self, "_probely_badge_lbl", None)
        if not (wrap and btn):
            return
        if status == "auth":
            fg = hbdr = T["ok"]
        elif status == "checking":
            fg = hbdr = T["muted"]
        else:  # unauth / unconfigured
            fg = hbdr = T["err"] if self._probely_configured() else T["muted"]
        try:
            wrap.configure(bg=hbdr)
            btn.configure(fg=fg, bg=T["panel_bg"], activeforeground=fg,
                          activebackground=T["surface2"])
        except Exception:
            pass

    def _set_probely_status(self, status: str):
        """status: 'unauth' (red/grey), 'checking' (grey), 'auth' (green)."""
        self._probely_auth_status = status
        self._update_probely_badge_style()
        # Keep the scan-tab Probely banner in sync if it exists.
        try:
            self._refresh_probely_banner()
        except Exception:
            pass

    def _validate_probely_key(self, *, on_done: Optional[Callable[[bool, str], None]] = None):
        """Validate the pasted Probely key against /profile/ on a background
        thread. Updates the badge and (optionally) calls on_done(ok, msg) on the
        UI thread via the event queue."""
        key = ""
        try:
            key = self._probely_key_var.get().strip()
        except Exception:
            pass
        if not key:
            self._set_probely_status("unauth")
            if on_done:
                on_done(False, "No hay clave de Probely para validar.")
            return
        # Make sure the shared store has the latest value before we validate.
        try: set_probely_key(key)
        except Exception: pass
        self._set_probely_status("checking")

        import types as _types
        cfg = _types.SimpleNamespace(
            probely_token=key,
            probely_auth_scheme="JWT",
            probely_api_base=(self._dast_apibase_var.get().strip()
                              if hasattr(self, "_dast_apibase_var") else ""),
            probely_region=(self._dast_region_var.get().lower()
                            if hasattr(self, "_dast_region_var") else ""))
        if cfg.probely_region in ("(predeterminado)", ""):
            cfg.probely_region = ""

        def _work():
            try:
                ok, msg = check_snyk_api_web(cfg, self._emit_log)
            except Exception as e:
                ok, msg = False, f"Error de validación: {e!r}"
            self._event_queue.put(("probely_validated", (ok, msg, on_done)))

        self._run_async(_work, label="validación de Probely")

    def _show_probely_key_popup(self):
        """Popup behind the 🌐 Probely badge: paste + validate a personal API key,
        with instructions to REQUEST a key from the Cybersecurity team (normal
        users don't have access to generate one themselves)."""
        import webbrowser as _wb
        status = getattr(self, "_probely_auth_status", "unauth")
        configured = self._probely_configured()
        if status == "auth":
            icon, icon_color, title = "✓", T["ok"], "Probely conectado"
            detail = "La clave de API de Probely fue validada correctamente."
            msg_fg = T["text"]
        elif configured:
            icon, icon_color, title = "!", T["accent"], "Clave sin validar"
            detail = ("Hay una clave de Probely guardada, pero aún no se ha "
                      "validado. Pulse «Validar» para comprobarla.")
            msg_fg = T["text"]
        else:
            icon, icon_color, title = "✕", T["err"], "Probely no conectado"
            detail = ("El escaneo en la nube (DAST / API) usa Snyk API & Web "
                      "(Probely), que requiere TU PROPIA clave de API — distinta "
                      "del inicio de sesión de Snyk. La emite el equipo de "
                      "Ciberseguridad; solicítala a slunam@bancobase.com.")
            msg_fg = T["err"]

        popup = self._create_popup("Clave de API de Probely")
        self._popup_hdr(popup, "Snyk API & Web (Probely)",
                        subtitle="Clave de API personal", icon="🌐")

        bg = T["bg"]
        body = tk.Frame(popup, bg=bg); body.pack(fill="both", expand=True)
        inner = tk.Frame(body, bg=bg, padx=40, pady=20); inner.pack(fill="both", expand=True)

        # Status line
        srow = tk.Frame(inner, bg=bg); srow.pack(fill="x", pady=(0, 12))
        tk.Label(srow, text=icon, font=(_FUI, 28), bg=bg, fg=icon_color).pack(side="left", padx=(0, 16))
        scol = tk.Frame(srow, bg=bg); scol.pack(side="left", fill="x", expand=True)
        tk.Label(scol, text=title, font=(_FUI, 15, "bold"), bg=bg, fg=T["text"],
                 anchor="w").pack(anchor="w")
        self._probely_popup_detail = tk.Label(scol, text=detail, font=(_FUI, 10),
                 bg=bg, fg=msg_fg, justify="left", anchor="w", wraplength=820)
        self._probely_popup_detail.pack(anchor="w", pady=(2, 0))

        tk.Frame(inner, bg=T["border_bg"], height=1).pack(fill="x", pady=(4, 12))

        # Instructions — keys are issued by Cybersecurity, NOT self-generated.
        steps = (
            "Cómo obtener tu clave de API:\n"
            "  •  Las claves de API de Probely las administra el equipo de Ciberseguridad;\n"
            "       los usuarios no las generan por su cuenta.\n"
            "  •  Solicítala al Líder de Ciberseguridad Digital: slunam@bancobase.com.\n"
            "  •  Indica tu nombre y el equipo / proyecto para el que la necesitas.\n"
            "  •  Recibirás una clave con el rol mínimo necesario. Pégala abajo."
        )
        tk.Label(inner, text=steps, font=(_FUI, 10), bg=bg, fg=T["muted"],
                 justify="left", anchor="w").pack(anchor="w")

        link_row = tk.Frame(inner, bg=bg); link_row.pack(anchor="w", pady=(8, 14))
        self._btn(link_row, "✉  Solicitar clave a Ciberseguridad",
                  lambda: _wb.open(
                      "mailto:slunam@bancobase.com"
                      "?subject=Solicitud%20de%20clave%20de%20API%20de%20Probely%20(BBScanner)"
                      "&body=Hola%2C%20solicito%20una%20clave%20de%20API%20de%20Probely%20"
                      "para%20BBScanner.%0A%0ANombre%3A%20%0AEquipo%2FProyecto%3A%20%0A"),
                  "outline").pack(side="left")

        tk.Frame(inner, bg=T["border_bg"], height=1).pack(fill="x", pady=(0, 12))

        # Paste field
        tk.Label(inner, text="Pega tu clave de API de Probely:", font=(_FUI, 10, "bold"),
                 bg=bg, fg=T["text"], anchor="w").pack(anchor="w", pady=(0, 4))
        entry_row = tk.Frame(inner, bg=bg); entry_row.pack(fill="x")
        entry_row.columnconfigure(0, weight=1)
        _show_var = tk.BooleanVar(value=False)
        key_entry = ttk.Entry(entry_row, textvariable=self._probely_key_var, show="*")
        key_entry.grid(row=0, column=0, sticky="ew")

        def _toggle_show():
            key_entry.config(show="" if _show_var.get() else "*")
        ttk.Checkbutton(entry_row, text="Mostrar", variable=_show_var,
                        command=_toggle_show).grid(row=0, column=1, padx=(8, 0))

        result_lbl = tk.Label(inner, text="", font=(_FUI, 10), bg=bg, fg=T["muted"],
                              justify="left", anchor="w", wraplength=820)
        result_lbl.pack(anchor="w", pady=(10, 0))

        def _on_validated(ok: bool, msg: str):
            try:
                result_lbl.config(text=("✓  " if ok else "✕  ") + msg,
                                  fg=T["ok"] if ok else T["err"])
            except Exception:
                pass

        def _do_validate():
            result_lbl.config(text="⏳  Validando…", fg=T["muted"])
            self._save_settings()
            self._validate_probely_key(on_done=_on_validated)

        self._popup_foot(
            popup,
            ("✓  Validar y guardar", _do_validate, "accent"),
            ("  Cerrar  ", popup.close, "flat"),
        )

    def _refresh_probely_banner(self, *_):
        """Show/hide the scan-tab Probely banner. The banner only matters when a
        web/api stage is selected AND no validated Probely key is present."""
        banner = getattr(self, "_probely_banner", None)
        if banner is None:
            return
        sv = getattr(self, "_scan_vars", {})
        needs = any(bool(sv.get(k) and sv[k].get()) for k in ("dast", "api"))
        ok = (getattr(self, "_probely_auth_status", "unauth") == "auth")
        show = needs and not ok
        visible = getattr(self, "_probely_banner_visible", False)
        if show and not visible:
            banner.pack(fill="x", pady=(0, 6),
                        after=getattr(self, "_auth_banner", None) or None)
            self._probely_banner_visible = True
        elif not show and visible:
            banner.pack_forget()
            self._probely_banner_visible = False
        # Update label wording based on whether a key is merely unvalidated.
        lbl = getattr(self, "_probely_banner_lbl", None)
        if lbl is not None:
            if self._probely_configured():
                lbl.config(text="Clave de Probely sin validar — haga clic para validar")
            else:
                lbl.config(text="Probely no conectado — se requiere para DAST / API")

    def _update_stop_btn_style(self):
        """Update stop button appearance based on scan state.
        Drives both the ribbon icon and the in-tab Stop button via state= only —
        never pack_forget so the button is always visible."""
        busy = self._any_busy()

        btn  = getattr(self, "_stop_icon_btn", None)
        wrap = getattr(self, "_stop_icon_wrap", None)
        if btn:
            if busy:
                if wrap:
                    try: wrap.configure(bg=T["err"])
                    except Exception: pass
                try:
                    btn.configure(state="normal", fg=T["err"],
                                  activeforeground=T["err"],
                                  activebackground=T["card_hover"],
                                  bg=T["panel_bg"])
                except Exception: pass
            else:
                if wrap:
                    try: wrap.configure(bg=T["muted"])
                    except Exception: pass
                try:
                    btn.configure(state="disabled", fg=T["muted"],
                                  activeforeground=T["muted"],
                                  activebackground=T["surface2"],
                                  bg=T["surface2"])
                except Exception: pass

        stop_btn = getattr(self, "_stop_scan_btn", None)
        if stop_btn:
            try:
                if busy:
                    stop_btn.config(state="normal",
                                    bg=T["surface2"], fg=T["err"],
                                    activebackground=T["card_hover"],
                                    activeforeground=T["err"])
                else:
                    stop_btn.config(state="disabled",
                                    bg=T["surface2"], fg=T["muted"])
            except Exception: pass

        self._refresh_scan_btn()

    def _set_status(self, s: str): self._status_var.set(s)
    def _emit_log(self, s: str):   self._event_queue.put(("log", s))

    def _flash_saved(self) -> None:
        """Briefly show '✔ Settings saved' in the status bar, then restore
        the previous status text. Safe to call from any thread via after()."""
        lbl = getattr(self, "_status_lbl", None)
        if lbl is None:
            return
        prev = self._status_var.get()
        fa = getattr(self, "_flash_after", None)
        if fa is not None:
            try: self.after_cancel(fa)
            except Exception: pass
        self._status_var.set("✔  Configuración guardada")
        try: lbl.config(fg=T["ok"])
        except Exception: pass
        def _restore():
            self._flash_after = None
            self._status_var.set(prev)
            try: lbl.config(fg=T["accent"])
            except Exception: pass
        self._flash_after = self.after(2200, _restore)


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
            try:
                self.transient(master)
            except Exception:
                pass
        _apply_palette(_splash_read_dark_pref())
        w, h = 640, 520
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")
        c = _apply_panel_chrome(self)

        # -- slim top strip: just OS/user meta now; branding lives in the hero below --
        ribbon = tk.Frame(c, bg=T["panel_bg"]); ribbon.pack(fill="x")
        tk.Frame(ribbon, bg=T["accent"], height=2).pack(fill="x", side="top")
        os_tag = "macOS" if IS_MAC else ("Windows" if IS_WIN else "Linux")
        tk.Label(ribbon, text=f"{os_tag}  \u00b7  {_detect_user()}", font=(_FUI, 9),
                 bg=T["panel_bg"], fg=T["muted"]).pack(side="right", padx=12, pady=6)
        tk.Frame(ribbon, bg=T["border_bg"], height=1).pack(fill="x", side="bottom")

        body = tk.Frame(c, bg=T["bg"]); body.pack(fill="both", expand=True, padx=22, pady=(12, 14))
        import math as _math, random as _random

        # -- hero: shield badge docked at the core of an animated scan ring --
        hero = tk.Frame(body, bg=T["bg"]); hero.pack(pady=(2, 8))

        GR, PAD = 88, 14
        GW = GH = GR * 2 + PAD * 2
        cx, cy = GW // 2, GH // 2
        self._globe_cv = tk.Canvas(hero, width=GW, height=GH, bg=T["bg"], bd=0, highlightthickness=0)
        self._globe_cv.pack()
        self._globe_angle = 0.0

        rnd = _random.Random(7)
        for _ in range(34):
            sx, sy = rnd.randint(0, GW), rnd.randint(0, GH)
            if (sx - cx) ** 2 + (sy - cy) ** 2 < (GR + PAD - 4) ** 2:
                continue
            r = rnd.choice((1, 1, 2))
            self._globe_cv.create_oval(sx - r, sy - r, sx + r, sy + r, fill=T["muted"], outline="")
        for i, stip in enumerate(("gray12", "gray25", "gray50")):
            rr = GR + (3 - i) * 4
            self._globe_cv.create_oval(cx - rr, cy - rr, cx + rr, cy + rr, outline=T["accent"], outlinestipple=stip)

        # shield badge at the centre — the asset the scan ring protects
        logo_w_target = 92
        try:
            self._splash_logo_img = tk.PhotoImage(file=str(LOGO_PATH))
            lw, lh = self._splash_logo_img.width(), self._splash_logo_img.height()
            factor = max(1, round(lw / logo_w_target)) if lw else 1
            if factor > 1:
                self._splash_logo_img = self._splash_logo_img.subsample(factor, factor)
            logo_w, logo_h = self._splash_logo_img.width(), self._splash_logo_img.height()
            cp = 12
            self._globe_cv.create_rectangle(cx - logo_w / 2 - cp, cy - logo_h / 2 - cp,
                                             cx + logo_w / 2 + cp, cy + logo_h / 2 + cp,
                                             fill=T["panel_bg"], outline=T["accent"], width=2)
            self._globe_cv.create_image(cx, cy, image=self._splash_logo_img)
        except Exception:
            self._globe_cv.create_oval(cx - 46, cy - 46, cx + 46, cy + 46, fill=T["accent"], outline="")
            self._globe_cv.create_text(cx, cy, text=APP_BRAND_NAME[:1], font=(_FUI, 32, "bold"),
                                       fill=T["button_fg"])

        def _draw_globe(angle):
            cv = self._globe_cv; cv.delete("globe")
            cv.create_oval(cx - GR, cy - GR, cx + GR, cy + GR, outline=T["accent"], width=2, tags="globe")
            cv.create_oval(cx - GR + 8, cy - GR + 8, cx + GR - 8, cy + GR - 8,
                           outline=T["muted"], width=1, tags="globe")
            for i in range(24):
                a = i * (2 * _math.pi / 24)
                r1, r2 = GR - 5, GR + (9 if i % 6 == 0 else 4)
                x1, y1 = cx + r1 * _math.cos(a), cy + r1 * _math.sin(a)
                x2, y2 = cx + r2 * _math.cos(a), cy + r2 * _math.sin(a)
                cv.create_line(x1, y1, x2, y2, fill=T["muted"], width=1, tags="globe")
            deg = _math.degrees(angle) % 360
            cv.create_arc(cx - GR, cy - GR, cx + GR, cy + GR, start=deg, extent=50,
                          style="arc", outline=T["accent"], width=4, tags="globe")
            for k, fade in ((3, "gray25"), (2, "gray50"), (1, None), (0, None)):
                a = angle * 2.4 - k * 0.20
                ox = cx + (GR + 16) * _math.cos(a); oy = cy + (GR + 16) * _math.sin(a)
                r = 3 if k == 0 else 2
                cv.create_oval(ox - r, oy - r, ox + r, oy + r, fill=T["accent"], outline="",
                               stipple=fade, tags="globe")

        def _spin_globe():
            if self._done or self._error is not None: return
            self._globe_angle = (self._globe_angle + 0.045) % (2 * _math.pi)
            _draw_globe(self._globe_angle); self.after(40, _spin_globe)

        _draw_globe(0.0); self.after(40, _spin_globe)

        tk.Label(hero, text=APP_BRAND_NAME, font=(_FUI, 15, "bold"),
                 bg=T["bg"], fg=T["accent"]).pack(pady=(10, 0))
        tk.Label(hero, text="Motor de escaneo de seguridad \u2014 cobertura continua", font=(_FUI, 9),
                 bg=T["bg"], fg=T["muted"]).pack()

        right_col = tk.Frame(body, bg=T["bg"]); right_col.pack(fill="both", expand=True, pady=(14, 0))
        self._step_var = tk.StringVar(value="Preparando…")
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

    def progress(self, kind, payload):
        self._q.put((kind, payload))

    def _append(self, text: str, tag: Optional[str] = None):
        self._log.configure(state="normal")
        start = self._log.index("end-1c")
        self._log.insert("end", text.rstrip() + "\n")
        if tag:
            self._log.tag_add(tag, start, "end-1c")
        lines = int(self._log.index("end-1c").split(".")[0])
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
                        self._step_var.set("✔  Listo — iniciando…")
                    self._pb.configure(value=100); self._done = True
        except queue.Empty:
            pass
        if self._done or self._error is not None:
            delay = 1800 if (self._done and self._warnings) else 280
            self.after(delay, self.destroy); return
        self.after(60, self._pump)


def run_boot(master: Optional[tk.Misc] = None) -> tuple[Optional[str], list[tuple[str, str]]]:
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
    master.wait_window(splash)
    if own_root:
        try: master.destroy()
        except Exception: pass
    return holder["error"], holder["warnings"]


def main():
    err, boot_warnings = run_boot()
    if err:
        msg = ("El escáner no pudo cargar sus dependencias:\n\n" + err +
               "\n\nNormalmente, un paquete faltante o proxy TLS corporativo.")
        try:
            root = tk.Tk(); root.withdraw()
            messagebox.showerror(f"{APP_BRAND_NAME} — error al inicio", msg)
        except Exception:
            print(msg, file=sys.stderr)
        return
    try:
        app = ScannerApp(boot_warnings=boot_warnings)
    except Exception as e:
        import traceback
        msg = (f"El escáner no pudo iniciar:\n\n{e!r}\n\n"
               "Normalmente, un paquete faltante o proxy TLS corporativo.\n\n" + traceback.format_exc())
        try:
            root = tk.Tk(); root.withdraw()
            messagebox.showerror(f"{APP_BRAND_NAME} — error al inicio", msg)
        except Exception:
            print(msg, file=sys.stderr)
        raise
    app.mainloop()


if __name__ == "__main__":
    main()