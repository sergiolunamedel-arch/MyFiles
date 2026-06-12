from __future__ import annotations

# ── Stage A: bootstrap ────────────────────────────────────────────────────────
# Heavy third-party deps are no longer installed at import time. Instead the
# loader below streams pip output to a real on-screen loading splash (see
# BootSplash / run_boot in the entry-point section) so the user can watch
# dependencies being downloaded, then the engine modules are imported.
import os, sys, shutil, subprocess
from pathlib import Path

# ── Platform detection (Windows / macOS / Linux) ──────────────────────────────
IS_WIN   = os.name == "nt"
IS_MAC   = sys.platform == "darwin"
IS_LINUX = not IS_WIN and not IS_MAC


def _pip(args: list[str], log=None) -> None:
    """Run pip --user, streaming each output line to `log` so the splash can
    reflect real download progress."""
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

    rc = _stream(cmd)
    if rc != 0:
        env = os.environ.copy()
        env["PIP_TRUSTED_HOST"] = "pypi.org files.pythonhosted.org pypi.python.org"
        hosts = ["--trusted-host", "pypi.org",
                 "--trusted-host", "files.pythonhosted.org",
                 "--trusted-host", "pypi.python.org"]
        if log: log("pip: retrying via trusted-host (corporate TLS proxy?)")
        rc = _stream(cmd + hosts, env=env)
        if rc != 0:
            raise subprocess.CalledProcessError(rc, cmd)
    import site
    us = site.getusersitepackages()
    if us not in sys.path:
        sys.path.insert(0, us)


def _ensure(import_name: str, pip_name: str | None = None, log=None) -> None:
    pip_name = pip_name or import_name

    def _drop():
        for m in list(sys.modules):
            if m == import_name or m.startswith(import_name + ".") \
               or m in ("markupsafe",) or m.startswith("markupsafe."):
                sys.modules.pop(m, None)

    for attempt in range(2):
        try:
            __import__(import_name)
            if log: log(f"{import_name}: already satisfied")
            return
        except ImportError as e:
            msg = str(e).lower()
            if log: log(f"{import_name}: not found — installing {pip_name}…")
            if import_name == "jinja2" and (
                    "soft_unicode" in msg or "markupsafe" in msg):
                _pip(["--upgrade", "--force-reinstall",
                      "Jinja2>=3.1", "MarkupSafe>=2.1"], log=log)
            elif attempt == 0:
                _pip(["--upgrade", pip_name], log=log)
            else:
                _pip(["--upgrade", "--force-reinstall", pip_name], log=log)
            _drop()
    __import__(import_name)


def _ensure_snyk_cli(log=None) -> None:
    """Ensure the Snyk CLI binary is available, downloading it once if needed.

    The binary is cached in a stable, well-known location:
      Linux / macOS : ~/.local/bin/snyk
      Windows       : %LOCALAPPDATA%\\snyk\\snyk.exe

    On every startup we inject that directory into PATH *before* calling
    shutil.which(), so a previously-downloaded binary is found immediately
    without requiring the user to edit their shell profile.

    A download only happens when the cached file is genuinely absent.
    """
    import urllib.request, stat, platform

    # ── 1. Resolve stable cache location ──────────────────────────────────────
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):    arch = "x64"
    elif machine in ("aarch64", "arm64"): arch = "arm64"
    else:                                  arch = "x64"

    if IS_WIN:
        suffix   = "win.exe"
        dest_dir = Path(os.environ.get("LOCALAPPDATA",
                        Path.home() / "AppData" / "Local")) / "snyk"
        bin_name = "snyk.exe"
    elif IS_MAC:
        suffix   = "macos" if arch != "arm64" else "macos-arm64"
        dest_dir = Path.home() / ".local" / "bin"
        bin_name = "snyk"
    else:
        suffix   = "linux" if arch != "arm64" else "linux-arm64"
        dest_dir = Path.home() / ".local" / "bin"
        bin_name = "snyk"

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / bin_name

    # ── 2. Always inject the cache dir into PATH for this process ─────────────
    # This is the key fix: even when the binary was downloaded in a previous
    # run, shutil.which("snyk") would return None if dest_dir isn't on the
    # inherited PATH. Prepend it unconditionally so the cached binary is found.
    path_env = os.environ.get("PATH", "")
    if str(dest_dir) not in path_env.split(os.pathsep):
        os.environ["PATH"] = str(dest_dir) + os.pathsep + path_env

    # ── 3. Check for an existing binary (cache hit) ───────────────────────────
    if dest.exists() and dest.stat().st_size > 1024:
        if log: log(f"snyk-cli: using cached binary at {dest}")
        return

    # Also accept any snyk already on the system PATH (npm -g install, brew, …)
    if shutil.which("snyk"):
        if log: log("snyk-cli: found on system PATH — skipping download")
        return

    # ── 4. Download (only runs on first launch or after manual deletion) ───────
    url = (f"https://github.com/snyk/snyk/releases/latest/download/"
           f"snyk-{suffix}")
    if log: log(f"snyk-cli: binary not found — downloading from {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SnykGUI/1.0"})
        # Stream into a temp file first; rename atomically on success
        tmp = dest.with_suffix(".tmp")
        with urllib.request.urlopen(req, timeout=60) as resp, open(tmp, "wb") as fh:
            while chunk := resp.read(65536):
                fh.write(chunk)
        if tmp.stat().st_size < 1024:
            tmp.unlink(missing_ok=True)
            raise ValueError("downloaded file is suspiciously small")
        if not IS_WIN:
            tmp.chmod(tmp.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        tmp.replace(dest)   # atomic on POSIX; best-effort on Windows
        if log: log(f"snyk-cli: downloaded and cached at {dest}")

        # ── 5. Persist dest_dir to shell profile (Unix only, best-effort) ─────
        # Prevents the "first startup per shell" flicker where which() misses
        # the binary before our PATH injection has run.
        if not IS_WIN:
            _persist_path_to_profile(dest_dir, log=log)

    except Exception as e:
        if log: log(f"snyk-cli: download failed ({e!r}) — manual install may be needed")
        raise


def _persist_path_to_profile(directory: Path, log=None) -> None:
    """Append an export PATH line to the user's shell profile (once only).

    Tries, in order: ~/.bashrc, ~/.zshrc, ~/.profile.
    Skips silently on any error — this is a convenience step, not required.
    """
    line = f'\nexport PATH="{directory}:$PATH"  # added by SnykGUI\n'
    candidates = [
        Path.home() / ".bashrc",
        Path.home() / ".zshrc",
        Path.home() / ".profile",
    ]
    for profile in candidates:
        try:
            if not profile.exists():
                continue
            existing = profile.read_text(encoding="utf-8", errors="ignore")
            if str(directory) in existing:
                return   # already present in this file — done
            profile.open("a", encoding="utf-8").write(line)
            if log: log(f"snyk-cli: added {directory} to {profile}")
            return
        except Exception:
            continue


# Steps shown on the loading splash. (import_name, pip_name, human label)
_BOOT_DEPS = [
    ("jinja2",            "Jinja2",            "Report templating engine"),
    ("selenium",          "selenium",          "Browser automation (DAST)"),
    ("webdriver_manager", "webdriver-manager", "WebDriver downloader"),
    ("pynput",            "pynput",            "Global hotkey listener (recorder)"),
]

# Populated by _load_runtime() after the deps are ready. The big class below
# references these as module globals, but only inside method bodies that run
# after the app has started, so deferring the import is safe.
_RUNTIME_READY = False
_GIT_SECRETS_STATUS: dict = {}


def _load_runtime(progress=None) -> None:
    """Ensure heavy deps + git-secrets, then import the engine modules into the
    module namespace. `progress(kind, payload)` is an optional callback:
        ('step', (i, total, label))   ('log', text)   ('error', text)
    """
    global _RUNTIME_READY, _GIT_SECRETS_STATUS

    def _log(text):
        if progress:
            try: progress("log", text)
            except Exception: pass

    total = len(_BOOT_DEPS) + 3  # deps + git-secrets + snyk-cli + engine import
    step = 0
    for import_name, pip_name, label in _BOOT_DEPS:
        step += 1
        if progress: progress("step", (step, total, f"{label} ({import_name})"))
        _ensure(import_name, pip_name, log=_log)

    # git-secrets auto-download (separate secrets module).
    step += 1
    if progress: progress("step", (step, total, "git-secrets (secret scanner)"))
    try:
        import secrets_scanner
        _GIT_SECRETS_STATUS = secrets_scanner.ensure_git_secrets(log=_log)
    except Exception as e:
        _log(f"secrets: git-secrets bootstrap skipped — {e!r}")
        _GIT_SECRETS_STATUS = {"available": False, "method": "builtin",
                               "note": f"{e!r}"}

    # Snyk CLI auto-download
    step += 1
    if progress: progress("step", (step, total, "Snyk CLI (vulnerability scanner)"))
    try:
        _ensure_snyk_cli(log=_log)
    except Exception as e:
        _log(f"snyk-cli: bootstrap skipped — {e!r}")

    # Engine modules (need jinja2 / selenium ready first).
    step += 1
    if progress: progress("step", (step, total, "Loading scanner engine…"))
    g = globals()
    import snyk_sca_sast as _sca
    for n in ("CheckResult", "check_python", "check_node", "check_npm",
              "check_snyk", "check_auth", "install_node", "install_snyk",
              "start_snyk_auth", "run_snyk_test", "run_snyk_code",
              "export_sarif", "export_merged_json"):
        g[n] = getattr(_sca, n)
    import dast_api as _dast
    for n in ("DastConfig", "ApiConfig", "run_dast", "run_api", "_make_driver",
              "_MACRO_JS", "_MACRO_DRAIN_JS", "_LOGOUT_CAPTURE_JS", "detect_browsers",
              "_replay_login_macro",
              "_api_load_spec", "_api_base_url", "_api_operations", "_make_opener"):
        g[n] = getattr(_dast, n)
    import report_engine as _rep
    for n in ("build_context", "build_cumulative_context", "export_csv", "render_html",
              "update_history_after_scan", "render_remediation_history",
              "add_remediation_action", "load_history", "ScanStateStore"):
        g[n] = getattr(_rep, n)
    import secrets_scanner as _sec
    for n in ("scan_path", "write_secrets_report", "ensure_git_secrets"):
        g[n] = getattr(_sec, n)
    g["secrets_scanner"] = _sec
    _RUNTIME_READY = True
    _log("Runtime ready.")


# ── Stage B: regular imports (standard library + tkinter, always available) ───
import json, queue, getpass, re as _re, threading, time, webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import tkinter as tk
from tkinter import ttk, messagebox, filedialog


# ── Cross-platform helpers ────────────────────────────────────────────────────
def _open_path(path) -> None:
    """Open a folder or file with the OS default handler (Win/macOS/Linux)."""
    p = str(path)
    try:
        if IS_WIN:
            os.startfile(p)            # type: ignore[attr-defined]
        elif IS_MAC:
            subprocess.Popen(["open", p])
        else:
            subprocess.Popen(["xdg-open", p])
    except Exception:
        try:
            webbrowser.open(Path(p).as_uri())
        except Exception:
            pass


def _detect_user() -> str:
    """Best-effort current-user detection (whoami-style)."""
    for getter in (
        lambda: getpass.getuser(),
        lambda: os.environ.get("USER") or os.environ.get("USERNAME") or os.environ.get("LOGNAME"),
    ):
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


# ── Constants ─────────────────────────────────────────────────────────────────
SCRIPT_DIR         = Path(__file__).resolve().parent
DEFAULT_TARGET     = SCRIPT_DIR / "Vulnerable"
DEFAULT_REPORTS    = SCRIPT_DIR / "Reports"
SETTINGS_FILE      = SCRIPT_DIR / ".scanner_settings.json"
AUTH_POLL_INTERVAL = 2
AUTH_POLL_TIMEOUT  = 300
SEVERITY_ORDER     = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# ── Fonts (platform-aware) ────────────────────────────────────────────────────
if IS_MAC:
    _FUI   = "SF Pro Text"      # falls back to system font if unavailable
    _FMONO = "Menlo"
elif IS_LINUX:
    _FUI   = "DejaVu Sans"
    _FMONO = "DejaVu Sans Mono"
else:
    _FUI   = "Segoe UI"
    _FMONO = "Cascadia Mono"

# ── Palette (Banco Base) ──────────────────────────────────────────────────────
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

# ── i18n ──────────────────────────────────────────────────────────────────────
_STR: dict[str, tuple[str, str]] = {
    'scan_title': ('▶  Scan Dashboard', '▶  Panel de Escaneo'),
    'env_title': ('🖥  Environment & Authentication', '🖥  Entorno y Autenticación'),
    'dast_title': ('🌐  Dynamic Application Security Testing (DAST)', '🌐  Pruebas Dinámicas de Seguridad (DAST)'),
    'api_title': ('🔌  API Security Scanning (OpenAPI / Swagger / Postman)', '🔌  Escaneo de API (OpenAPI / Swagger / Postman)'),
    'reports_title': ('📋  Reports', '📋  Reportes'),
    'settings_title': ('⚙  Settings', '⚙  Ajustes'),
    'run_pipeline': ('▶  Run Pipeline', '▶  Ejecutar Pipeline'),
    'stop': ('■  Stop', '■  Detener'),
    'open_report': ('🌐 Open last report', '🌐 Abrir último reporte'),
    'export_csv': ('💾 Export CSV…', '💾 Exportar CSV…'),
    'browse': ('Browse…', 'Explorar…'),
    'pipeline': ('PIPELINE', 'PIPELINE'),
    'folders': ('FOLDERS', 'CARPETAS'),
    'target_folder': ('📂 Target folder', '📂 Carpeta objetivo'),
    'open_viewer': ('📋 Reports viewer', '📋 Visor de reportes'),
    'recheck': ('🔄 Re-check', '🔄 Re-verificar'),
    'login_snyk': ('🔑 Login with Snyk', '🔑 Iniciar sesión con Snyk'),
    'no_reports_yet': ('(no reports yet — run a scan)', '(sin reportes — ejecute un escaneo)'),
    'nothing_to_cancel': ('nothing to cancel.', 'nada que cancelar.'),
    'cancel_requested': ('cancel requested…', 'cancelación solicitada…'),
    'cancelling': ('Cancelling…', 'Cancelando…'),
    'initialising': ('Initialising…', 'Inicializando…'),
    'ready': ('Ready.', 'Listo.'),
    'env_prerequisites': ('PREREQUISITES', 'REQUISITOS PREVIOS'),
    'env_auth_row': ('Authentication', 'Autenticación'),
    'sett_reports_folder_card': ('REPORTS FOLDER', 'CARPETA DE REPORTES'),
    'sett_lang_card': ('LANGUAGE / IDIOMA', 'IDIOMA / LANGUAGE'),
    'sett_theme_card': ('THEME', 'TEMA'),
    'sett_misc_card': ('SCAN BEHAVIOUR', 'COMPORTAMIENTO DE ESCANEO'),
    'sett_interface_lang': ('Interface language:', 'Idioma de la interfaz:'),
    'sett_color_theme': ('Color theme:', 'Tema de color:'),
    'sett_max_log': ('Max console log lines:', 'Máx. líneas en consola:'),
    'sett_auto_open_cb': ('Auto-open report in browser after scan', 'Abrir reporte en navegador automáticamente'),
    'sett_confirm_del_cb': ('Confirm before deleting reports', 'Confirmar antes de eliminar reportes'),
    'recent_scans': ('RECENT SCANS', 'ESCANEOS RECIENTES'),
    'stage_sca_tip': ('Open-source / Software Composition Analysis.\nScans package manifests (package.json, requirements.txt, pom.xml…)\nfor known CVEs using the Snyk vulnerability database.\nRequires Node.js, npm and Snyk CLI.', 'Análisis de Composición de Software (SCA / Open Source).\nEscanea manifiestos de paquetes (package.json, requirements.txt, pom.xml…)\nen busca de CVEs conocidos usando la base de datos de vulnerabilidades Snyk.\nRequiere Node.js, npm y Snyk CLI.'),
    'stage_code_tip': ('Static Application Security Testing.\nAnalyses source code for security anti-patterns without running it.\nPowered by Snyk Code (DeepCode AI engine).\nRequires Node.js, npm and Snyk CLI.', 'Análisis Estático de Seguridad (SAST).\nAnaliza el código fuente en busca de patrones de seguridad inseguros sin ejecutarlo.\nImpulsado por Snyk Code (motor DeepCode AI).\nRequiere Node.js, npm y Snyk CLI.'),
    'stage_dast_tip': ('Dynamic Application Security Testing.\nSpiders a live running application and checks headers, cookies,\ninfo leaks, and optionally injects XSS/SQLi payloads.\nConfigure target URL and auth in the DAST tab.', 'Pruebas Dinámicas de Seguridad de Aplicaciones (DAST).\nRecorre una aplicación en ejecución y verifica cabeceras, cookies,\nfugas de información y opcionalmente inyecta payloads XSS/SQLi.\nConfigure la URL objetivo y la autenticación en la pestaña DAST.'),
    'stage_api_tip': ('API Security Scanning.\nReads an OpenAPI/Swagger/Postman spec and tests every endpoint\nfor auth bypass, info leaks, XSS, SQLi, and open redirects.\nConfigure the spec path and auth in the API Scan tab.', 'Escaneo de Seguridad de API.\nLee una especificación OpenAPI/Swagger/Postman y prueba cada endpoint\nen busca de bypass de autenticación, fugas de información, XSS, SQLi y redirecciones abiertas.\nConfigure la ruta de la especificación y la autenticación en la pestaña API Scan.'),
    'stage_sca_name': ('Open-source (SCA)', 'Open-source (SCA)'),
    'stage_sca_desc': ('Scans dependency manifests for known CVEs via Snyk.', 'Escanea manifiestos de dependencias en busca de CVEs conocidos via Snyk.'),
    'stage_code_name': ('Static code (SAST)', 'Código estático (SAST)'),
    'stage_code_desc': ('Finds security issues in source files via Snyk Code.', 'Encuentra problemas de seguridad en archivos fuente via Snyk Code.'),
    'stage_dast_name': ('Dynamic (DAST)', 'Dinámico (DAST)'),
    'stage_dast_desc': ('Crawls a live URL and optionally injects probes. Configure in DAST tab.', 'Rastrea una URL en vivo y opcionalmente inyecta sondas. Configurar en pestaña DAST.'),
    'stage_api_name': ('API Security', 'Seguridad de API'),
    'stage_api_desc': ('Probes every endpoint in an OpenAPI/Swagger/Postman spec. Configure in API Scan tab.', 'Sondea cada endpoint en una especificación OpenAPI/Swagger/Postman. Configurar en API Scan.'),
    'target_folder_tip': ('Root folder of the project to scan.\nSCA and SAST will recursively search this folder for manifests and source files.', 'Carpeta raíz del proyecto a escanear.\nSCA y SAST buscarán recursivamente manifiestos y archivos fuente en esta carpeta.'),
    'env_python_tip': ('Python 3.9 or newer is required to run this scanner.\nThis check verifies the interpreter version in use.', 'Se requiere Python 3.9 o superior para ejecutar este escáner.\nEsta verificación valida la versión del intérprete en uso.'),
    'env_node_tip': ("Node.js is required to run the Snyk CLI.\nInstall from https://nodejs.org/ (LTS version recommended).\nOn Windows, click 'Fix' to auto-install via winget.", "Node.js es necesario para ejecutar el Snyk CLI.\nInstalar desde https://nodejs.org/ (versión LTS recomendada).\nEn Windows, haz clic en 'Fix' para instalar automáticamente via winget."),
    'env_npm_tip': ('npm (Node Package Manager) is bundled with Node.js.\nRequired to install the Snyk CLI globally.', 'npm (Node Package Manager) viene incluido con Node.js.\nRequerido para instalar el Snyk CLI de forma global.'),
    'env_snyk_tip': ("Snyk CLI is the engine for SCA and SAST scans.\nInstall with: npm install -g snyk\nClick 'Fix' to install automatically.", "Snyk CLI es el motor para escaneos SCA y SAST.\nInstalar con: npm install -g snyk\nHaz clic en 'Fix' para instalar automáticamente."),
    'env_auth_tip': ("Authentication token or SSO session for Snyk.\nClick 'Login with Snyk' to open the browser auth flow.\nRequired for SCA and SAST scans.", "Token de autenticación o sesión SSO para Snyk.\nHaz clic en 'Iniciar sesión con Snyk' para abrir el flujo de autenticación en el navegador.\nRequerido para escaneos SCA y SAST."),
    'env_fix_tip': ('Auto-install or configure', 'Instalar o configurar automáticamente'),
    'env_recheck_tip': ('Re-run all environment checks now.\nUse this after installing Node.js, npm, or Snyk CLI.', 'Volver a ejecutar todas las verificaciones de entorno ahora.\nÚsalo después de instalar Node.js, npm o Snyk CLI.'),
    'env_login_tip': ('Opens the Snyk authentication flow in your browser.\nAfter logging in, the token is stored in the Snyk CLI config.\nRequired for SCA and SAST scans.', 'Abre el flujo de autenticación de Snyk en el navegador.\nDespués de iniciar sesión, el token se guarda en la configuración del Snyk CLI.\nRequerido para escaneos SCA y SAST.'),
    'dast_target_card': ('TARGET & PROFILE', 'OBJETIVO Y PERFIL'),
    'dast_url_lbl': ('Target URL', 'URL objetivo'),
    'dast_url_tip': ('Root URL of the running application.\nThe crawler starts here and follows links.', 'URL raíz de la aplicación en ejecución.\nEl rastreador comienza aquí y sigue enlaces.'),
    'dast_auth_lbl': ('Auth type', 'Tipo de autenticación'),
    'dast_auth_tip': ('none / basic / bearer / cookie / header / form / selenium', 'none / basic / bearer / cookie / header / form / selenium'),
    'dast_profile_lbl': ('Profile', 'Perfil'),
    'dast_profile_tip': ('passive — safe, read-only checks (headers, cookies, info leaks)\nactive  — also sends XSS/SQLi/open-redirect payloads.\nOnly run active against systems you are authorised to test.', "passive — verificaciones seguras de solo lectura (cabeceras, cookies, fugas de info)\nactive  — también envía payloads XSS/SQLi/redirección abierta.\nSolo ejecuta 'active' contra sistemas que estás autorizado a probar."),
    'dast_max_pages_lbl': ('Max pages', 'Máx. páginas'),
    'dast_max_pages_tip': ('Maximum number of distinct pages to crawl before stopping.', 'Número máximo de páginas distintas a rastrear antes de detenerse.'),
    'dast_subdomains_tip': ('Also crawl links on subdomains of the target host.', 'También rastrear enlaces en subdominios del host objetivo.'),
    'dast_tls_tip': ('Validate HTTPS certificate. Untick for self-signed / staging certs.', 'Validar certificado HTTPS. Desmarcar para certs auto-firmados / staging.'),
    'dast_relogin_tip': ('Re-authenticate automatically if the session expires mid-scan.', 'Re-autenticar automáticamente si la sesión expira durante el escaneo.'),
    'dast_exclude_lbl': ('Exclude URL regex', 'Regex de exclusión de URLs'),
    'dast_exclude_tip': ("URLs matching this regex are skipped.\nDefault excludes logout links so the session isn't killed.", 'Las URLs que coincidan con esta regex se omiten.\nPor defecto excluye enlaces de logout para no cerrar la sesión.'),
    'dast_rate_lbl': ('Rate (req/s)', 'Velocidad (req/s)'),
    'dast_rate_tip': ('Max requests per second to avoid overloading the target.', 'Máximo de peticiones por segundo para no sobrecargar el objetivo.'),
    'dast_workers_lbl': ('Workers', 'Workers'),
    'dast_workers_tip': ('Parallel workers for disclosure probing, crawling and active probes.\nThe req/s rate limit is still enforced across all workers.\nAuto re-login (form/selenium auth) forces sequential mode for safety.', 'Workers paralelos para rastreo y sondas activas.\nEl límite de req/s se aplica a todos los workers.\nRe-login automático (form/selenium) fuerza modo secuencial por seguridad.'),
    'dast_proxy_lbl': ('HTTP proxy', 'Proxy HTTP'),
    'dast_proxy_tip': ('Optional proxy URL, e.g. http://127.0.0.1:8080 for Burp/ZAP.', 'URL de proxy opcional, ej. http://127.0.0.1:8080 para Burp/ZAP.'),
    'dast_sel_card': ('SELENIUM LOGIN  (auth = selenium only)', 'LOGIN SELENIUM  (solo cuando auth = selenium)'),
    'dast_browser_lbl': ('Browser', 'Navegador'),
    'dast_browser_tip': ('Only browsers detected on this machine are listed.\nThe matching WebDriver is resolved automatically (Selenium Manager,\nwith webdriver-manager as fallback).\nSupports Chrome, Edge, Firefox, Brave, Opera, Opera GX, Vivaldi & Chromium.', 'Solo se listan los navegadores detectados en esta máquina.\nEl WebDriver correspondiente se resuelve automáticamente (Selenium Manager,\ncon webdriver-manager como respaldo).\nSoporta Chrome, Edge, Firefox, Brave, Opera, Opera GX, Vivaldi y Chromium.'),
    'dast_headless_tip': ('Run the browser without a visible window.\nDisable (untick) to debug login flows — the browser will appear on screen.', 'Ejecutar el navegador sin ventana visible.\nDesmarcar para depurar flujos de login — el navegador aparecerá en pantalla.'),
    'dast_login_timeout_lbl': ('Login timeout (s)', 'Timeout de login (s)'),
    'dast_login_timeout_tip': ('Seconds to wait for elements during the Selenium login sequence.\nIncrease for slow-loading SPAs or MFA flows.', 'Segundos a esperar por elementos durante la secuencia de login Selenium.\nIncrementar para SPAs lentas o flujos con MFA.'),
    'api_spec_card': ('SPEC & TARGET', 'ESPECIFICACIÓN Y OBJETIVO'),
    'api_spec_lbl': ('Spec (URL or file)', 'Especificación (URL o archivo)'),
    'api_spec_tip': ('OpenAPI v2/v3, Swagger, or Postman collection.\nAccepts a URL (https://host/openapi.json) or local .json/.yaml path.', 'OpenAPI v2/v3, Swagger o colección Postman.\nAcepta una URL (https://host/openapi.json) o ruta local .json/.yaml.'),
    'api_base_lbl': ('Base URL override', 'Override URL base'),
    'api_base_tip': ("Force the base URL when the spec has no 'servers' declaration.\nLeave blank to use the URL from the spec file.", "Forzar la URL base cuando la especificación no tiene declaración 'servers'.\nDejar vacío para usar la URL del archivo de especificación."),
    'api_auth_lbl': ('Auth type', 'Tipo de autenticación'),
    'api_auth_tip': ('none / basic / bearer / cookie / header', 'none / basic / bearer / cookie / header'),
    'api_profile_lbl': ('Profile', 'Perfil'),
    'api_profile_tip': ('passive — auth/header/CORS checks only (safe)\nactive  — also fuzzes query params and JSON bodies for XSS / SQLi / open redirect', "passive — verificaciones de auth/cabecera/CORS solo (seguro)\nactive  — también fuzzea parámetros de consulta y cuerpos JSON"),
    'api_max_ep_lbl': ('Max endpoints', 'Máx. endpoints'),
    'api_max_ep_tip': ('Maximum number of API endpoints to test per scan run.', 'Número máximo de endpoints de API a probar por ejecución.'),
    'api_tls_tip': ('Validate HTTPS certificates.\nUntick for self-signed or staging certs.', 'Validar certificados HTTPS.\nDesmarcar para certs auto-firmados o de staging.'),
    'api_exclude_lbl': ('Exclude regex', 'Regex de exclusión'),
    'api_exclude_tip': ("Endpoints whose URL matches this regex are skipped.", 'Los endpoints cuya URL coincida con esta regex se omiten.'),
    'api_proxy_lbl': ('HTTP proxy', 'Proxy HTTP'),
    'api_proxy_tip': ('Optional proxy URL, e.g. http://127.0.0.1:8080 for Burp Suite / ZAP.', 'URL de proxy opcional, ej. http://127.0.0.1:8080 para Burp Suite / ZAP.'),
    'api_conv_card': ('SPEC CONVERTER & ENDPOINT PREVIEW', 'CONVERTIDOR DE ESPECIFICACIÓN Y VISTA PREVIA DE ENDPOINTS'),
    'api_preview_btn': ('🔍 Preview', '🔍 Preview'),
    'api_import_btn': ('📥 Import…', '📥 Importar…'),
}
_LANGS = ("en", "es")
_current_lang = "en"

def _t(key: str) -> str:
    pair = _STR.get(key)
    if pair is None: return key
    return pair[1] if _current_lang == "es" else pair[0]

# ── Platform utils ────────────────────────────────────────────────────────────
def _which(cmd: str) -> Optional[str]:
    if (f := shutil.which(cmd)):
        return f
    if os.name == "nt":
        for ext in (".cmd", ".bat", ".exe"):
            if (f := shutil.which(cmd + ext)):
                return f
    return None

def _run(args, cwd=None, env=None, timeout=600) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, cwd=str(cwd) if cwd else None,
        env=env if env is not None else os.environ.copy(),
        timeout=timeout, capture_output=True, text=True,
        encoding="utf-8", errors="replace", shell=False)

def _ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# ── Theme helpers ─────────────────────────────────────────────────────────────
_ROLE_BG = {
    _PALETTE_LIGHT["bg"]:       "bg",       _PALETTE_DARK["bg"]:       "bg",
    _PALETTE_LIGHT["panel_bg"]: "panel_bg", _PALETTE_DARK["panel_bg"]: "panel_bg",
    _PALETTE_LIGHT["surface2"]: "surface2", _PALETTE_DARK["surface2"]: "surface2",
}
_ROLE_FG = {
    _PALETTE_LIGHT["text"]:  "text",  _PALETTE_DARK["text"]:  "text",
    _PALETTE_LIGHT["muted"]: "muted", _PALETTE_DARK["muted"]: "muted",
    _PALETTE_LIGHT["ok"]:    "ok",    _PALETTE_DARK["ok"]:    "ok",
}
_ROLE_BTN_BG = {
    _PALETTE_LIGHT["panel_bg"]: "panel_bg", _PALETTE_DARK["panel_bg"]: "panel_bg",
    _PALETTE_LIGHT["surface2"]: "surface2", _PALETTE_DARK["surface2"]: "surface2",
}
_ROLE_ACCENT = {
    _PALETTE_LIGHT["accent"]:  "accent",  _PALETTE_DARK["accent"]:  "accent",
    _PALETTE_LIGHT["accent2"]: "accent2", _PALETTE_DARK["accent2"]: "accent2",
}
_BORDERS = (_PALETTE_LIGHT["border"], _PALETTE_DARK["border"])

def _apply_palette(dark: bool) -> None:
    src = _PALETTE_DARK if dark else _PALETTE_LIGHT
    T.update(src)
    T["highlight"]      = T["accent"]
    T["highlight_text"] = T["button_fg"]
    T["tree_bg"]        = T["panel_bg"]
    T["button_hover"]   = T["accent_hi"]

# ── Tooltip ───────────────────────────────────────────────────────────────────
class _Tooltip:
    def __init__(self, widget, text: str):
        self._text = text; self._tip = None
        widget.bind("<Enter>",   self._show, "+")
        widget.bind("<Leave>",   self._hide, "+")
        widget.bind("<Destroy>", self._hide, "+")

    def _show(self, event=None):
        if self._tip: return
        x = event.widget.winfo_rootx() + 20
        y = event.widget.winfo_rooty() + event.widget.winfo_height() + 4
        self._tip = tw = tk.Toplevel()
        tw.wm_overrideredirect(True); tw.wm_geometry(f"+{x}+{y}")
        tk.Label(tw, text=self._text, justify="left", relief="solid", bd=1,
                 font=(_FUI, 9), bg="#ffffcc", fg="#111827",
                 wraplength=340, padx=6, pady=4).pack()

    def _hide(self, event=None):
        if self._tip:
            try: self._tip.destroy()
            except Exception: pass
            self._tip = None

# ── Tree / Reports helpers ────────────────────────────────────────────────────
def _fill_tree_row(tree: "ttk.Treeview", d: Path) -> None:
    meta: dict = {}
    mf = d / "meta.json"
    if mf.exists():
        try: meta = json.loads(mf.read_text(encoding="utf-8"))
        except Exception: pass
    counts = meta.get("counts") or {}
    tree.insert("", "end", iid=str(d), values=(
        meta.get("generated_at") or d.name.replace("report_", ""),
        meta.get("mode", "?"), meta.get("total", "?"),
        counts.get("critical", "?"), counts.get("high", "?"),
        counts.get("medium", "?"), counts.get("low", "?"),
        meta.get("target", "")))

def _make_tree(parent, cols, headings, height) -> "ttk.Treeview":
    tree = ttk.Treeview(parent, columns=cols, show="headings", height=height)
    for c, (txt, w) in zip(cols, headings):
        tree.heading(c, text=txt)
        tree.column(c, width=w, anchor="w")
    tree.pack(side="left", fill="both", expand=True)
    ttk.Scrollbar(parent, command=tree.yview, orient="vertical").pack(side="right", fill="y")
    return tree

def _center_over(master, win, w_pct: float, h_pct: float) -> None:
    master.update_idletasks()
    ax, ay = master.winfo_rootx(), master.winfo_rooty()
    aw, ah = master.winfo_width(), master.winfo_height()
    w, h = int(aw * w_pct), int(ah * h_pct)
    win.geometry(f"{w}x{h}+{ax + (aw - w) // 2}+{ay + (ah - h) // 2}")

# ── Reports viewer popup ──────────────────────────────────────────────────────
class ReportsViewer(tk.Toplevel):
    def __init__(self, master, root_path: Path):
        super().__init__(master)
        self._root_path = root_path
        self._app  = master
        self.transient(master)
        _center_over(master, self, 0.72, 0.70)
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.update_idletasks(); self.lift(); self.focus_force()
        try: self.grab_set()
        except tk.TclError: pass

        def _close():
            try: self.grab_release()
            except Exception: pass
            self.destroy()
            try: master.focus_force()
            except Exception: pass

        self.bind("<Escape>", lambda e: _close())
        border = tk.Frame(self, bg=T["accent"], padx=2, pady=2)
        border.pack(fill="both", expand=True)
        content = tk.Frame(border, bg=T["bg"])
        content.pack(fill="both", expand=True)

        hdr_bg = T["panel_bg"]
        hdr = tk.Frame(content, bg=hdr_bg, padx=30, pady=14); hdr.pack(fill="x")
        row = tk.Frame(hdr, bg=hdr_bg); row.pack(fill="x")
        tk.Label(row, text="📋  Report History", font=(_FUI, 14, "bold"),
                 bg=hdr_bg, fg=T["accent"]).pack(side="left")
        tk.Label(row, text=str(root_path), font=(_FUI, 10, "italic"),
                 bg=hdr_bg, fg=T["muted"]).pack(side="left", padx=(12, 0))
        for txt, cmd in [("🔄 Refresh", self._refresh),
                         ("📁 Open folder", self._open_root)]:
            tk.Button(row, text=txt, command=cmd,
                      bg=T["accent"], fg=T["button_fg"],
                      activebackground=T["button_hover"], activeforeground=T["button_fg"],
                      font=(_FUI, 10), relief="flat", padx=8, pady=3,
                      cursor="hand2").pack(side="right", padx=(4, 0))
        tk.Frame(content, bg=T["border"], height=1).pack(fill="x")

        tree_wrap = tk.Frame(content, bg=T["bg"])
        tree_wrap.pack(fill="both", expand=True, padx=18, pady=(14, 6))
        cols = ("when", "mode", "total", "critical", "high", "medium", "low", "target")
        self._tree = _make_tree(tree_wrap, cols, [
            ("Generated", 160), ("Mode", 80), ("Total", 60),
            ("Crit", 50), ("High", 50), ("Med", 50), ("Low", 50),
            ("Target", 340)], height=16)
        self._tree.bind("<Double-1>", lambda _: self._open_html())

        tk.Frame(content, bg=T["border"], height=1).pack(fill="x")
        foot = tk.Frame(content, bg=T["panel_bg"], padx=20, pady=10); foot.pack(fill="x")
        tk.Button(foot, text="✕  Close", command=_close,
                  bg=T["accent"], fg=T["button_fg"],
                  activebackground=T["button_hover"], activeforeground=T["button_fg"],
                  font=(_FUI, 11, "bold"), relief="flat", padx=14, pady=6,
                  cursor="hand2").pack(side="right", padx=(6, 0))
        for txt, cmd in [("🗑 Delete", self._delete),
                         ("🧬 Export SARIF…", self._export_sarif),
                         ("💾 Export CSV…", self._export_csv),
                         ("📁 Open folder", self._open_selected),
                         ("▶ Open HTML", self._open_html)]:
            tk.Button(foot, text=txt, command=cmd,
                      bg=T["surface2"], fg=T["text"],
                      activebackground=T["card_hover"], activeforeground=T["accent"],
                      font=(_FUI, 11), relief="flat", padx=10, pady=6,
                      cursor="hand2").pack(side="left", padx=(0, 6))
        self._refresh()

    def _scan_dirs(self) -> list[tuple[Path, dict]]:
        out = []
        for d in sorted(self._root_path.iterdir()
                        if self._root_path.exists() else [], reverse=True):
            if not d.is_dir() or not d.name.startswith("report_"): continue
            meta: dict = {}
            mf = d / "meta.json"
            if mf.exists():
                try: meta = json.loads(mf.read_text(encoding="utf-8"))
                except Exception: pass
            out.append((d, meta))
        return out

    def _refresh(self):
        for iid in self._tree.get_children(): self._tree.delete(iid)
        for d, _ in self._scan_dirs(): _fill_tree_row(self._tree, d)

    def _sel(self):
        s = self._tree.selection(); return Path(s[0]) if s else None

    def _open_root(self):
        _open_path(self._root_path)

    def _open_selected(self):
        if d := self._sel():
            _open_path(d)

    def _open_html(self):
        d = self._sel()
        if not d: return
        html = d / "report.html"
        if html.exists(): webbrowser.open(html.as_uri())
        else: self._app._show_warn_popup("Open HTML", f"No report.html in:\n{d}")

    def _export_csv(self):
        d = self._sel()
        if not d: return
        src = d / "findings.csv"
        if not src.exists():
            self._app._show_warn_popup("Export CSV", f"No findings.csv in:\n{d}"); return
        path = filedialog.asksaveasfilename(
            title="Export CSV", defaultextension=".csv",
            initialdir=str(d), initialfile="findings.csv",
            filetypes=[("CSV", "*.csv"), ("All", "*.*")])
        if not path: return
        import shutil; shutil.copyfile(src, path)
        self._app._show_info_popup("Export CSV", f"Wrote {path}")

    def _export_sarif(self):
        d = self._sel()
        if not d: return
        if not any((d / n).exists() for n in (
                "snyk_test.json", "snyk_code.json", "dast.json", "api.json")):
            self._app._show_warn_popup("Export SARIF",
                f"No raw scan output in:\n{d}"); return
        try:
            sarif = export_sarif(d)
            export_merged_json(d)
        except Exception as e:
            self._app._show_error_popup("Export SARIF", f"Failed:\n{e}"); return
        if not sarif:
            self._app._show_warn_popup("Export SARIF",
                "Nothing to export — no findings were assembled."); return
        path = filedialog.asksaveasfilename(
            title="Export SARIF", defaultextension=".sarif",
            initialdir=str(d), initialfile="findings.sarif",
            filetypes=[("SARIF", "*.sarif *.json"), ("All", "*.*")])
        if not path:
            self._app._show_info_popup("Export SARIF",
                f"SARIF written in report folder:\n{sarif}"); return
        try:
            import shutil; shutil.copyfile(sarif, path)
        except Exception as e:
            self._app._show_error_popup("Export SARIF", f"Could not copy:\n{e}"); return
        self._app._show_info_popup("Export SARIF", f"Wrote {path}")

    def _delete(self):
        d = self._sel()
        if not d: return
        if getattr(self._app, "_confirm_del", True):
            if not self._app._ask_yesno_popup("Delete report",
                                               f"Delete entire folder?\n\n{d}"): return
        try:
            import shutil; shutil.rmtree(d); self._refresh()
        except Exception as e:
            self._app._show_error_popup("Delete", f"Failed:\n{e}")

# ── Main application ──────────────────────────────────────────────────────────
class ScannerApp(tk.Tk):
    """Vulnerability Scanner — Integrated.py look & feel."""

    _CRED_KEYS = [
        "username", "password", "token", "cookie", "header_name", "header_value",
        "login_url", "login_data", "selenium_login_url", "selenium_user_selector",
        "selenium_user_value", "selenium_pass_selector", "selenium_pass_value",
        "selenium_submit_selector", "selenium_extra_steps", "selenium_macro",
        "login_success_selector", "login_success_text", "logout_url_re",
    ]
    _DAST_AUTH_FIELDS = {
        "none":     [],
        "basic":    [("username", "Username", False), ("password", "Password", True)],
        "bearer":   [("token", "Bearer token", True)],
        "cookie":   [("cookie", "Cookie header value", False)],
        "header":   [("header_name", "Header name", False), ("header_value", "Header value", True)],
        "form":     [("username", "Username", False), ("password", "Password", True),
                     ("login_url", "Login POST URL", False), ("login_data", "POST body", False)],
        "selenium": [("selenium_login_url", "Login page URL", False),
                     ("selenium_user_selector", "Username CSS selector", False),
                     ("selenium_user_value", "Username value", False),
                     ("selenium_pass_selector", "Password CSS selector", False),
                     ("selenium_pass_value", "Password value", True),
                     ("selenium_submit_selector", "Submit CSS selector", False),
                     ("selenium_extra_steps", "Extra steps JSON", False)],
    }
    _SESSION_FIELDS = [
        ("login_success_selector", "Logged-in CSS selector"),
        ("login_success_text",     "Logged-in text marker"),
        ("logout_url_re",          "Logout URL regex"),
    ]

    def __init__(self):
        super().__init__()
        self.title("Vulnerability Scanner")
        self.configure(bg=T["bg"])
        self._user = _detect_user()
        # Wipe in-memory secrets (recorded password, tokens) when the app closes.
        try:
            self.protocol("WM_DELETE_WINDOW", self._on_app_close)
        except Exception:
            pass
        try:
            if IS_WIN:
                self.state("zoomed")
            elif IS_MAC:
                # macOS has no "-zoomed"; size to the screen instead.
                sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
                self.geometry(f"{sw}x{sh}+0+0")
                try: self.state("zoomed")
                except Exception: pass
            else:
                self.attributes("-zoomed", True)
        except Exception:
            self.geometry("1400x900")

        self.fonts = {
            "title":   (_FUI, 28, "bold"), "heading": (_FUI, 18, "bold"),
            "sub":     (_FUI, 13, "bold"), "body":    (_FUI, 12),
            "small":   (_FUI, 11),         "caption": (_FUI, 10),
            "mono":    (_FMONO, 11),       "tab":     (_FUI, 11, "bold"),
            "emoji":   (_FUI, 14),
        }

        self._event_queue: queue.Queue = queue.Queue()
        self._auth_proc: Optional[subprocess.Popen] = None
        self._auth_deadline = 0.0
        self._target       = DEFAULT_TARGET
        self._reports_root = DEFAULT_REPORTS
        self._last_report: Optional[Path] = None
        self._last_context: Optional[dict] = None
        self._last_report_dir: Optional[Path] = None
        self._last_secrets_html: Optional[Path] = None
        self._secrets_busy = False
        self._checks: dict[str, CheckResult] = {}
        self._busy         = False
        self._cancel_evt   = threading.Event()
        self._console_visible = False
        self._unread_log   = 0
        self._active_tab: str = "scan"

        # ── App Inventory ─────────────────────────────────────────────────────
        self._inv_tab: Optional[Any] = None          # AppInventoryTab instance
        self._active_app: Optional[dict] = None      # currently selected profile

        self._dark_mode    = False
        self._lang         = "en"
        self._auto_open    = True
        self._confirm_del  = True
        self._max_log_lines= 2000
        self._load_settings()

        # Inventory store (needs _reports_root which is set in _load_settings)
        from app_inventory import AppInventoryStore
        self._inv_store = AppInventoryStore(self._reports_root)

        # Cumulative scan-state store (last raw output per scan type)
        from report_engine import ScanStateStore
        self._scan_state = ScanStateStore(self._reports_root)

        self._setup_styles()
        self._build_vars()
        self._build_ui()

        self.after(150, self._drain_events)
        self.after(300, lambda: self._run_async(self._recheck, label="initial env check"))

    # ── Settings persistence ──────────────────────────────────────────────────
    def _load_settings(self):
        global _current_lang
        if not SETTINGS_FILE.exists(): return
        try:
            data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except Exception: return
        if "dark_mode" in data:
            self._dark_mode = bool(data["dark_mode"])
            _apply_palette(self._dark_mode)
        if "lang" in data and data["lang"] in _LANGS:
            self._lang = data["lang"]
            _current_lang = self._lang
        if data.get("reports_root"):
            self._reports_root = Path(data["reports_root"])
        if "auto_open"     in data: self._auto_open      = bool(data["auto_open"])
        if "confirm_del"   in data: self._confirm_del    = bool(data["confirm_del"])
        if "max_log_lines" in data: self._max_log_lines  = int(data["max_log_lines"])

    def _save_settings(self):
        data = {
            "dark_mode":     self._dark_mode,
            "lang":          self._lang,
            "reports_root":  str(self._reports_root),
            "auto_open":     self._auto_open,
            "confirm_del":   self._confirm_del,
            "max_log_lines": self._max_log_lines,
        }
        try:
            SETTINGS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            self._emit_log(f"[settings] could not save: {e}")

    # ── Theme ─────────────────────────────────────────────────────────────────
    def _apply_theme_to_app(self):
        _apply_palette(self._dark_mode)
        self._setup_styles()
        self._recolour_widget(self)
        self._recolour_ribbon_tabs()

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
        checks = getattr(self, "_checks", {})
        env_has_issues = bool(checks) and not (
            all((checks.get(k) and checks[k].ok) for k in ("python", "node", "npm", "snyk"))
            and bool(checks.get("auth") and checks["auth"].ok))
        for k, btn in getattr(self, "_ribbon_tabs", {}).items():
            try:
                if k == active:
                    btn.config(bg=T["accent"], fg=T["button_fg"])
                else:
                    fg = T["err"] if (k == "env" and env_has_issues) else T["text"]
                    btn.config(bg=T["panel_bg"], fg=fg,
                               activebackground=T["card_hover"],
                               activeforeground=T["accent"])
            except Exception: pass
        for attr, bg_key, hi_key in (
            ("_run_icon_btn",  None, None),
            ("_stop_icon_btn", None, None),
        ):
            btn = getattr(self, attr, None)
            if btn:
                try:
                    # Preserve white background + colored outline style
                    if attr == "_run_icon_btn":
                        btn.configure(fg=T["accent"],
                                      highlightbackground=T["accent"],
                                      highlightcolor=T["accent"])
                    else:
                        # stop button color depends on scan state
                        self._update_stop_btn_style()
                except Exception: pass

    def _setup_styles(self):
        s = ttk.Style(self)
        try: s.theme_use("clam")
        except tk.TclError: pass
        f = (_FUI, 12)
        s.configure(".", background=T["bg"], foreground=T["text"], font=f)
        for name, bg in [("TFrame", T["bg"]), ("Card.TFrame", T["panel_bg"]),
                         ("Surface.TFrame", T["panel_bg"])]:
            s.configure(name, background=bg)
        for name, bg, fg in [
            ("TLabel",        T["bg"],       T["text"]),
            ("Surface.TLabel",T["panel_bg"], T["text"]),
            ("Muted.TLabel",  T["bg"],       T["muted"]),
            ("MutedS.TLabel", T["panel_bg"], T["muted"]),
            ("Section.TLabel",T["panel_bg"], T["muted"]),
        ]:
            s.configure(name, background=bg, foreground=fg)
        s.configure("Section.TLabel", font=(_FUI, 10, "bold"))
        s.configure("TButton", background=T["surface2"], foreground=T["text"],
                    bordercolor=T["border"], padding=(10, 6), relief="flat")
        s.map("TButton", background=[("active", T["card_hover"]),
                                     ("disabled", T["surface2"])],
              foreground=[("disabled", T["muted"])])
        for name, bg, bga in [("Accent.TButton", T["accent"], T["accent_hi"]),
                               ("Danger.TButton", T["accent2"], T["accent2_hi"])]:
            s.configure(name, background=bg, foreground=T["button_fg"],
                        font=(_FUI, 11, "bold"), padding=(14, 8))
            s.map(name, background=[("active", bga), ("disabled", T["surface2"])],
                  foreground=[("disabled", T["muted"])])
        s.configure("Ghost.TButton", background=T["panel_bg"], foreground=T["text"],
                    bordercolor=T["border"], relief="solid", borderwidth=1, padding=(8, 5))
        s.map("Ghost.TButton",
              background=[("active", T["surface2"]), ("disabled", T["panel_bg"])],
              foreground=[("disabled", T["muted"])])
        s.configure("TEntry", fieldbackground=T["surface2"], foreground=T["text"],
                    bordercolor=T["border"], padding=5)
        s.map("TEntry", bordercolor=[("focus", T["accent"])])
        s.configure("TCombobox", fieldbackground=T["surface2"], foreground=T["text"],
                    arrowcolor=T["accent"])
        s.map("TCombobox", fieldbackground=[("readonly", T["surface2"])],
              selectbackground=[("readonly", T["accent"])],
              selectforeground=[("readonly", T["button_fg"])])
        s.configure("TCheckbutton", background=T["panel_bg"], foreground=T["text"])
        s.map("TCheckbutton", background=[("active", T["card_hover"])])
        s.configure("TSpinbox", fieldbackground=T["surface2"], foreground=T["text"])
        s.configure("Treeview", background=T["panel_bg"], foreground=T["text"],
                    fieldbackground=T["panel_bg"], rowheight=26,
                    selectbackground=T["accent"], selectforeground=T["button_fg"])
        s.configure("Treeview.Heading", background=T["accent"],
                    foreground=T["button_fg"], font=(_FUI, 11, "bold"), relief="flat")
        s.configure("Vertical.TScrollbar", background=T["panel_bg"],
                    troughcolor=T["bg"], bordercolor=T["border"])

    # ── Variables ─────────────────────────────────────────────────────────────
    def _build_vars(self):
        self._target_var  = tk.StringVar(value=str(self._target))
        self._reports_var = tk.StringVar(value=str(self._reports_root))
        self._scan_vars   = {k: tk.BooleanVar(value=(k in ("sca", "code")))
                             for k in ("sca", "code", "dast", "api", "secrets")}
        self._dast_url_var      = tk.StringVar(value="https://")
        self._dast_auth_var     = tk.StringVar(value="none")
        self._dast_profile_var  = tk.StringVar(value="passive")
        self._dast_pages_var    = tk.IntVar(value=30)
        self._dast_subs_var     = tk.BooleanVar(value=False)
        self._dast_tls_var      = tk.BooleanVar(value=True)
        self._dast_relogin_var  = tk.BooleanVar(value=True)
        self._dast_exclude_var  = tk.StringVar(value=r"(?i)/(logout|signout|sign-out|log-out|api/logout)\b")
        self._dast_rps_var      = tk.DoubleVar(value=8.0)
        self._dast_workers_var  = tk.IntVar(value=4)
        self._dast_proxy_var    = tk.StringVar(value="")
        self._dast_browser_var  = tk.StringVar(value="chrome")        # key (source of truth)
        self._dast_browser_label_var = tk.StringVar(value="Google Chrome")
        self._browser_catalog   = {}    # {key: {"name","binary","engine"}}
        self._browser_label_key = {}    # {label: key}
        self._dast_headless_var = tk.BooleanVar(value=True)
        self._dast_selwait_var  = tk.IntVar(value=15)
        self._dast_cred_vars    = {k: tk.StringVar() for k in self._CRED_KEYS}
        self._api_spec_var      = tk.StringVar(value="")
        self._api_base_var      = tk.StringVar(value="")
        self._api_auth_var      = tk.StringVar(value="none")
        self._api_profile_var   = tk.StringVar(value="passive")
        self._api_pages_var     = tk.IntVar(value=80)
        self._api_tls_var       = tk.BooleanVar(value=True)
        self._api_rps_var       = tk.DoubleVar(value=8.0)
        self._api_workers_var   = tk.IntVar(value=6)
        self._api_proxy_var     = tk.StringVar(value="")
        self._api_exclude_var   = tk.StringVar(value=r"(?i)/(logout|signout|sign-out|log-out)\b")
        self._api_cred_vars     = {k: tk.StringVar() for k in
                                   ("username", "password", "token", "cookie",
                                    "header_name", "header_value")}
        self._status_var    = tk.StringVar(value=_t("initialising"))
        self._stage_pills: dict[str, tk.Label] = {}
        self._recent_paths: list[Path] = []

    # ── Top-level UI ──────────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_ribbon()
        self._build_body()
        self._build_status_bar()
        self._show_tab("scan")

    def _build_ribbon(self):
        self._ribbon = tk.Frame(self, bg=T["panel_bg"],
                                highlightthickness=1,
                                highlightbackground=T["border"])
        self._ribbon.pack(side="top", fill="x")
        tk.Frame(self._ribbon, bg=T["accent"], height=2).pack(fill="x", side="top")
        inner_row = tk.Frame(self._ribbon, bg=T["panel_bg"])
        inner_row.pack(fill="x", side="top")
        brand = tk.Frame(inner_row, bg=T["panel_bg"], padx=10, pady=0)
        brand.pack(side="left")
        tk.Frame(brand, bg=T["accent2"], height=2).pack(fill="x", side="top")
        brand_inner = tk.Frame(brand, bg=T["panel_bg"], pady=1)
        brand_inner.pack(fill="x")
        tk.Label(brand_inner, text="🛡", font=(_FUI, 18),
                 bg=T["panel_bg"], fg=T["accent"]).pack(side="left", padx=(0, 4))
        tk.Label(brand_inner, text="BBSCANNER",
                 font=(_FUI, 11, "bold"),
                 bg=T["panel_bg"], fg=T["accent"]).pack(side="left")
        self._ribbon_tabs: dict[str, tk.Button] = {}
        tabs = [("scan","▶ Scan"),("env","🖥 Env"),("dast","🌐 DAST"),
                ("api","🔌 API"),("secrets","🔑 Secrets"),
                ("reports","📋 Reports"),("apps","📦 Apps"),
                ("settings","⚙ Settings")]
        tab_area = tk.Frame(inner_row, bg=T["panel_bg"])
        tab_area.pack(side="left", fill="y")
        for key, label in tabs:
            btn = tk.Button(
                tab_area, text=label, command=lambda k=key: self._show_tab(k),
                bg=T["panel_bg"], fg=T["text"], font=(_FUI, 10, "bold"),
                relief="flat", bd=0, padx=10, pady=6, cursor="hand2",
                justify="center", activebackground=T["card_hover"],
                activeforeground=T["accent"])
            btn.bind("<Enter>", lambda e, b=btn:
                b.config(bg=T["card_hover"])
                if b != self._ribbon_tabs.get(self._active_tab) else None)
            btn.bind("<Leave>", lambda e, b=btn:
                b.config(bg=T["panel_bg"])
                if b != self._ribbon_tabs.get(self._active_tab) else None)
            btn.pack(side="left", fill="y", padx=1)
            self._ribbon_tabs[key] = btn
        right = tk.Frame(inner_row, bg=T["panel_bg"])
        right.pack(side="right", padx=8)
        self._run_icon_btn = tk.Button(
            right, text="▶", font=(_FUI, 14, "bold"),
            command=self._start_scan,
            bg="#ffffff", fg=T["accent"],
            activebackground=T["surface2"], activeforeground=T["accent"],
            relief="solid", bd=2, padx=8, pady=4, cursor="hand2",
            highlightthickness=2, highlightbackground=T["accent"],
            highlightcolor=T["accent"],
            state="disabled")
        self._run_icon_btn.pack(side="left", padx=(0, 4))
        _Tooltip(self._run_icon_btn, _t("run_pipeline"))
        self._stop_icon_btn = tk.Button(
            right, text="■", font=(_FUI, 14, "bold"),
            command=self._request_cancel,
            bg="#ffffff", fg=T["muted"],
            activebackground=T["surface2"], activeforeground=T["muted"],
            relief="solid", bd=2, padx=8, pady=4, cursor="hand2",
            highlightthickness=2, highlightbackground=T["muted"],
            highlightcolor=T["muted"])
        self._stop_icon_btn.pack(side="left", padx=(0, 8))
        _Tooltip(self._stop_icon_btn, _t("stop"))
        tk.Frame(self._ribbon, bg=T["border"], height=1).pack(fill="x", side="bottom")

    def _show_tab(self, key: str):
        self._active_tab = key
        checks = getattr(self, "_checks", {})
        env_has_issues = bool(checks) and not (
            all((checks.get(k) and checks[k].ok) for k in ("python","node","npm","snyk"))
            and bool(checks.get("auth") and checks["auth"].ok))
        for k, btn in self._ribbon_tabs.items():
            if k == key:
                btn.config(bg=T["accent"], fg=T["button_fg"])
            else:
                if k == "env" and env_has_issues:
                    btn.config(bg=T["panel_bg"], fg=T["err"])
                else:
                    btn.config(bg=T["panel_bg"], fg=T["text"])
        for k, frame in self._tab_frames.items():
            if k == key: frame.tkraise()

    def _build_body(self):
        body = tk.Frame(self, bg=T["bg"])
        body.pack(side="top", fill="both", expand=True)
        self._console_frame = tk.Frame(body, bg=T["panel_bg"],
                                       highlightthickness=1,
                                       highlightbackground=T["border"])
        self._build_console(self._console_frame)
        stack = tk.Frame(body, bg=T["bg"])
        stack.pack(side="top", fill="both", expand=True)
        self._tab_frames: dict[str, tk.Frame] = {}
        builders = {
            "scan":     self._build_tab_scan,
            "env":      self._build_tab_env,
            "dast":     self._build_tab_dast,
            "api":      self._build_tab_api,
            "secrets":  self._build_tab_secrets,
            "reports":  self._build_tab_reports,
            "apps":     self._build_tab_apps,
            "settings": self._build_tab_settings,
        }
        for key, builder in builders.items():
            f = tk.Frame(stack, bg=T["bg"])
            f.place(x=0, y=0, relwidth=1, relheight=1)
            builder(f)
            self._tab_frames[key] = f

    def _build_status_bar(self):
        bar = tk.Frame(self, bg=T["panel_bg"], pady=5,
                       highlightthickness=1,
                       highlightbackground=T["border"])
        bar.pack(side="bottom", fill="x")
        self._console_btn = tk.Button(
            bar, text="▥  Console", command=self._toggle_console,
            font=self.fonts["caption"], bg=T["panel_bg"], fg=T["muted"],
            relief="flat", padx=8, pady=0, cursor="hand2",
            activebackground=T["card_hover"])
        self._console_btn.pack(side="left", padx=8)
        # Detected user (whoami) + OS tag, right-aligned.
        os_tag = "macOS" if IS_MAC else ("Windows" if IS_WIN else "Linux")
        user_box = tk.Frame(bar, bg=T["panel_bg"]); user_box.pack(side="right", padx=10)
        tk.Label(user_box, text=f"  ·  {os_tag}", font=self.fonts["caption"],
                 bg=T["panel_bg"], fg=T["muted"]).pack(side="right")
        user_lbl = tk.Label(user_box, text=f"👤 {self._user}",
                            font=self.fonts["caption"],
                            bg=T["panel_bg"], fg=T["text"])
        user_lbl.pack(side="right")
        _Tooltip(user_lbl, "Current user detected on this machine (whoami).")
        tk.Label(bar, textvariable=self._status_var,
                 font=self.fonts["caption"],
                 bg=T["panel_bg"], fg=T["accent"],
                 anchor="center").pack(expand=True)

    def _build_console(self, parent):
        hdr = tk.Frame(parent, bg=T["accent"], padx=10, pady=6)
        hdr.pack(fill="x")
        tk.Label(hdr, text="ACTIVITY LOG", font=(_FUI, 11, "bold"),
                 bg=T["accent"], fg=T["button_fg"]).pack(side="left")
        tk.Button(hdr, text="✕ Close", command=self._toggle_console,
                  bg=T["accent"], fg=T["button_fg"],
                  activebackground=T["button_hover"], activeforeground=T["button_fg"],
                  font=self.fonts["small"], relief="flat", padx=8,
                  cursor="hand2").pack(side="right")
        inner = tk.Frame(parent, bg=T["surface2"])
        inner.pack(fill="both", expand=True)
        self._log_widget = tk.Text(
            inner, wrap="word", font=self.fonts["mono"],
            bg=T["surface2"], fg=T["text"],
            insertbackground=T["text"], relief="flat",
            padx=12, pady=8, height=10, state="disabled")
        self._log_widget.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(inner, command=self._log_widget.yview)
        sb.pack(side="right", fill="y")
        self._log_widget.configure(yscrollcommand=sb.set)

    def _toggle_console(self):
        if self._console_visible:
            self._console_frame.pack_forget()
            self._console_visible = False
        else:
            self._console_frame.pack(side="bottom", fill="x")
            self._console_visible = True
            self._unread_log = 0
        self._console_btn.configure(text="▥  Console")

    # ── Shared UI helpers ─────────────────────────────────────────────────────
    def _scrollable(self, parent, pad=(18, 12, 18, 8)) -> tk.Frame:
        canvas = tk.Canvas(parent, bg=T["bg"], highlightthickness=0, bd=0)
        vsb    = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        holder = tk.Frame(canvas, bg=T["bg"])
        win    = canvas.create_window((0, 0), window=holder, anchor="nw")
        holder.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win, width=e.width))
        def wheel(e): canvas.yview_scroll(int(-e.delta / 120), "units")
        canvas.bind("<Enter>", lambda _: canvas.bind_all("<MouseWheel>", wheel))
        canvas.bind("<Leave>", lambda _: canvas.unbind_all("<MouseWheel>"))
        inner = tk.Frame(holder, bg=T["bg"], padx=pad[0], pady=pad[1])
        inner.pack(fill="both", expand=True)
        return inner

    def _section_header(self, parent, text: str) -> tk.Frame:
        f = tk.Frame(parent, bg=T["panel_bg"], padx=14, pady=6)
        f.pack(fill="x")
        tk.Label(f, text=text, font=(_FUI, 13, "bold"),
                 bg=T["panel_bg"], fg=T["accent"], anchor="w").pack(side="left")
        return f

    def _card(self, parent, title="", *, pady=(0, 10)) -> tk.Frame:
        outer = tk.Frame(parent, bg=T["panel_bg"],
                         highlightthickness=1, highlightbackground=T["border"])
        outer.pack(fill="x", pady=pady)
        if title:
            hdr = tk.Frame(outer, bg=T["accent"], padx=14, pady=5)
            hdr.pack(fill="x")
            tk.Label(hdr, text=title, font=(_FUI, 10, "bold"),
                     bg=T["accent"], fg=T["button_fg"], anchor="w").pack(side="left")
        inner = tk.Frame(outer, bg=T["panel_bg"], padx=14, pady=10)
        inner.pack(fill="both", expand=True)
        return inner

    def _side_card(self, row, title, *, padx=(0, 0), pad=14, ipady=10) -> tk.Frame:
        outer = tk.Frame(row, bg=T["panel_bg"],
                         highlightthickness=1, highlightbackground=T["border"])
        outer.pack(side="left", fill="both", expand=True, padx=padx)
        hdr = tk.Frame(outer, bg=T["accent"], padx=pad, pady=5); hdr.pack(fill="x")
        tk.Label(hdr, text=title, font=(_FUI, 10, "bold"),
                 bg=T["accent"], fg=T["button_fg"], anchor="w").pack(side="left")
        inner = tk.Frame(outer, bg=T["panel_bg"], padx=pad, pady=ipady)
        inner.pack(fill="both", expand=True)
        return inner

    def _lbl(self, parent, text="", size=11, bold=False, bg=None, fg=None, **kw) -> tk.Label:
        sty = "bold" if bold else "normal"
        return tk.Label(parent, text=text, font=(_FUI, size, sty),
                        bg=bg or T["panel_bg"], fg=fg or T["text"], **kw)

    def _btn(self, parent, text, cmd, kind="accent", **kw) -> tk.Button:
        _base_pad = (12, 7); _base_font = (_FUI, 11, "bold")
        p = parent; is_in_ribbon = False
        try:
            while p is not None:
                if getattr(self, "_ribbon", None) is p:
                    is_in_ribbon = True; break
                p = getattr(p, "master", None)
        except Exception: is_in_ribbon = False
        if is_in_ribbon:
            kinds = {
                "accent":  dict(bg=T["accent"],   fg=T["button_fg"],
                                activebackground=T["accent_hi"],  activeforeground=T["button_fg"],
                                font=_base_font, padx=_base_pad[0], pady=_base_pad[1]),
                "danger":  dict(bg=T["accent2"],  fg=T["button_fg"],
                                activebackground=T["accent2_hi"], activeforeground=T["button_fg"],
                                font=_base_font, padx=_base_pad[0], pady=_base_pad[1]),
                "outline": dict(bg=T["panel_bg"], fg=T["accent"],
                                activebackground=T["card_hover"], activeforeground=T["accent_hi"],
                                font=_base_font, padx=_base_pad[0], pady=_base_pad[1],
                                borderwidth=1, relief="solid"),
                "flat":    dict(bg=T["surface2"], fg=T["text"],
                                activebackground=T["card_hover"], activeforeground=T["accent"],
                                font=(_FUI, 11), padx=10, pady=5),
            }
            cfg = kinds.get(kind, kinds["flat"])
        else:
            container = tk.Frame(parent, bg=T["accent"])
            inner_btn = tk.Button(container, text=text, command=cmd,
                                  bg=T["panel_bg"], fg=T["accent"],
                                  activebackground=T["card_hover"],
                                  activeforeground=T["accent_hi"],
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
        if tip: _Tooltip(w, tip)
        return w

    def _spin(self, parent, label, var, frm, to, tip, *, inc=None, width=6, padx=(0, 0)):
        if label:
            self._lbl(parent, label, size=10, fg=T["muted"]).pack(side="left", padx=(0, 4))
        kw = dict(from_=frm, to=to, textvariable=var, width=width)
        if inc is not None: kw["increment"] = inc
        sp = ttk.Spinbox(parent, **kw)
        sp.pack(side="left", padx=padx)
        _Tooltip(sp, tip)
        return sp

    def _gentry(self, parent, var, row, col, tip="", *, span=1, **grid_kw):
        e = ttk.Entry(parent, textvariable=var)
        e.grid(row=row, column=col, columnspan=span, sticky="ew", pady=3, **grid_kw)
        if tip: _Tooltip(e, tip)
        return e

    def _hdiv(self, parent, **pk) -> tk.Frame:
        f = tk.Frame(parent, bg=T["border"], height=1)
        f.pack(fill="x", **pk)
        return f

    def _create_popup(self, title: str = "Window",
                      w_pct: float = 0.55, h_pct: float = 0.60) -> tk.Frame:
        win = tk.Toplevel(self)
        win.title(title); win.configure(bg=T["bg"]); win.transient(self)
        _center_over(self, win, w_pct, h_pct)
        win.overrideredirect(True); win.attributes("-topmost", True)
        win.update_idletasks(); win.lift(); win.focus_force()
        try: win.grab_set()
        except tk.TclError: pass

        def _close():
            try: win.grab_release()
            except Exception: pass
            win.destroy()
            try: self.focus_force()
            except Exception: pass

        win.bind("<Escape>", lambda e: _close())
        border = tk.Frame(win, bg=T["accent"], padx=2, pady=2)
        border.pack(fill="both", expand=True)
        content = tk.Frame(border, bg=T["bg"])
        content.pack(fill="both", expand=True)
        content.close = _close          # type: ignore[attr-defined]
        content._win  = win             # type: ignore[attr-defined]
        return content

    def _popup_hdr(self, popup: tk.Frame, title: str,
                   subtitle: str = "", icon: str = "") -> tk.Frame:
        bg = T["panel_bg"]
        hdr = tk.Frame(popup, bg=bg, padx=30, pady=16); hdr.pack(fill="x")
        row = tk.Frame(hdr, bg=bg); row.pack(fill="x")
        label_text = f"{icon}  {title}" if icon else title
        tk.Label(row, text=label_text, font=(_FUI, 14, "bold"),
                 bg=bg, fg=T["accent"]).pack(side="left")
        if subtitle:
            tk.Label(row, text=subtitle, font=(_FUI, 11, "italic"),
                     bg=bg, fg=T["muted"]).pack(side="left", padx=(10, 0))
        self._hdiv(popup)
        return hdr

    def _popup_foot(self, popup: tk.Frame, *items,
                    padx: int = 28, pady: int = 12,
                    with_status: bool = False):
        bg = T["panel_bg"]
        self._hdiv(popup)
        bar = tk.Frame(popup, bg=bg, padx=padx, pady=pady); bar.pack(fill="x")
        status_lbl = None
        if with_status:
            status_lbl = tk.Label(bar, text="", font=(_FUI, 10), bg=bg, fg=T["muted"])
            status_lbl.pack(side="left")
        for text, cmd, kind in items:
            self._btn(bar, text, cmd, kind).pack(side="right", padx=(6, 0))
        return (bar, status_lbl) if with_status else bar

    def _show_popup(self, title: str, message: str, kind: str = "info"):
        icon = {"info": "ℹ", "warn": "⚠", "error": "✕"}.get(kind, "ℹ")
        fg   = T["err"] if kind == "error" else T["text"]
        w_pct, h_pct = (0.38, 0.28) if kind == "error" else (0.35, 0.25)
        popup = self._create_popup(title, w_pct=w_pct, h_pct=h_pct)
        self._popup_hdr(popup, title, icon=icon)
        body = tk.Frame(popup, bg=T["bg"], padx=36, pady=24); body.pack(fill="both", expand=True)
        tk.Label(body, text=message, font=(_FUI, 11), bg=T["bg"], fg=fg,
                 justify="left", wraplength=520).pack(anchor="w")
        self._popup_foot(popup, ("OK", popup.close, "accent"))

    def _show_info_popup(self, title, message):  self._show_popup(title, message, "info")
    def _show_warn_popup(self, title, message):  self._show_popup(title, message, "warn")
    def _show_error_popup(self, title, message): self._show_popup(title, message, "error")

    def _ask_yesno_popup(self, title: str, message: str) -> bool:
        result: list[bool] = [False]
        popup = self._create_popup(title, w_pct=0.35, h_pct=0.25)
        self._popup_hdr(popup, title, icon="?")
        body = tk.Frame(popup, bg=T["bg"], padx=36, pady=24); body.pack(fill="both", expand=True)
        tk.Label(body, text=message, font=(_FUI, 11), bg=T["bg"], fg=T["text"],
                 justify="left", wraplength=500).pack(anchor="w")
        def _yes(): result[0] = True; popup.close()
        self._popup_foot(popup, ("Cancel", popup.close, "flat"), ("Yes", _yes, "accent"))
        self.wait_window(popup._win)
        return result[0]

    # ── Tab: Scan ─────────────────────────────────────────────────────────────
    def _build_tab_scan(self, parent):
        self._section_header(parent, _t("scan_title"))
        pad = self._scrollable(parent)

        # ── Active App Context Banner ─────────────────────────────────────────
        app_banner = tk.Frame(pad, bg=T["surface2"],
                              highlightthickness=1,
                              highlightbackground=T["border"])
        app_banner.pack(fill="x", pady=(0, 8))
        banner_inner = tk.Frame(app_banner, bg=T["surface2"], padx=14, pady=7)
        banner_inner.pack(fill="x")
        tk.Label(banner_inner, text="📦  Active App:",
                 font=(_FUI, 10, "bold"), bg=T["surface2"],
                 fg=T["muted"]).pack(side="left")
        self._active_app_lbl = tk.Label(
            banner_inner, text="None — go to 📦 Apps tab to load a profile",
            font=(_FUI, 10), bg=T["surface2"], fg=T["muted"])
        self._active_app_lbl.pack(side="left", padx=(8, 0))
        tk.Button(
            banner_inner, text="📦 Switch App",
            command=lambda: self._show_tab("apps"),
            bg=T["surface2"], fg=T["accent"],
            font=(_FUI, 10), relief="flat", padx=8,
            cursor="hand2", activebackground=T["card_hover"],
            activeforeground=T["accent_hi"],
        ).pack(side="right")

        pipe = self._card(pad, _t("pipeline"))
        _STAGE_TIPS = {k: _t(f"stage_{k}_tip") for k in ("sca","code","dast","api")}
        _STAGE_TIPS["secrets"] = (
            "Secret / Credential Scanning.\n"
            "Walks the target folder and flags hard-coded credentials, tokens, and\n"
            "private keys using the built-in regex engine (modelled on git-secrets)\n"
            "plus the real git-secrets binary when available.\n"
            "Findings are tagged CWE-798 and appear in the unified report."
        )
        _STAGE_INFO = [
            ("sca",     "1", _t("stage_sca_name"),  _t("stage_sca_desc")),
            ("code",    "2", _t("stage_code_name"), _t("stage_code_desc")),
            ("dast",    "3", _t("stage_dast_name"), _t("stage_dast_desc")),
            ("api",     "4", _t("stage_api_name"),  _t("stage_api_desc")),
            ("secrets", "5", "Secret Scanning",
             "Hard-coded credentials, tokens & keys  (CWE-798 · git-secrets + built-in)"),
        ]
        for key, num, name, desc in _STAGE_INFO:
            row = tk.Frame(pipe, bg=T["panel_bg"]); row.pack(fill="x", pady=2)
            pill = tk.Label(row, text="Not running", font=(_FUI, 10),
                            bg=T["pill_idle_bg"], fg=T["pill_idle_fg"], padx=6, pady=1)
            pill.pack(side="left", padx=(0, 8))
            _Tooltip(pill, _STAGE_TIPS.get(key, desc))
            self._lbl(row, num, size=12, bold=True, fg=T["muted"],
                      anchor="center", width=2).pack(side="left")
            cb = tk.Checkbutton(row, variable=self._scan_vars[key],
                                command=self._refresh_scan_btn,
                                bg=T["panel_bg"], activebackground=T["card_hover"],
                                cursor="hand2")
            cb.pack(side="left", padx=(2, 6))
            _Tooltip(cb, _STAGE_TIPS.get(key, desc))
            info = tk.Frame(row, bg=T["panel_bg"]); info.pack(side="left", fill="x", expand=True)
            self._lbl(info, name, size=11, bold=True).pack(anchor="w")
            self._lbl(info, desc, size=10, fg=T["muted"]).pack(anchor="w")
            self._stage_pills[key] = pill

        row2 = tk.Frame(pad, bg=T["bg"]); row2.pack(fill="x", pady=(0, 4))
        cfg_card = self._side_card(row2, _t("folders"), padx=(0, 6), pad=14, ipady=12)
        for label, var, title_str, tip in [
            (_t("target_folder"), self._target_var, "Choose target folder to scan",
             _t("target_folder_tip")),
        ]:
            row = tk.Frame(cfg_card, bg=T["panel_bg"]); row.pack(fill="x", pady=3)
            lbl = self._lbl(row, label + ":", size=10, fg=T["muted"], width=16, anchor="w")
            lbl.pack(side="left"); _Tooltip(lbl, tip)
            self._lbl(row, "", size=10, textvariable=var, anchor="w").pack(side="left", fill="x", expand=True)
            def _browse(v=var, t=title_str):
                d = filedialog.askdirectory(title=t, initialdir=v.get() or str(SCRIPT_DIR))
                if d: v.set(d)
            self._btn(row, _t("browse"), _browse, kind="flat").pack(side="right")

        self._scan_btn = tk.Button(pad, state="disabled")
        self._open_btn = tk.Button(pad, state="disabled")
        self._csv_btn  = tk.Button(pad, state="disabled")
        self._recent_lb = tk.Listbox(pad); self._recent_lb.pack_forget()

    # ── Tab: Environment ──────────────────────────────────────────────────────
    def _build_tab_env(self, parent):
        self._section_header(parent, _t("env_title"))
        pad = self._scrollable(parent)
        env_card = self._card(pad, _t("env_prerequisites"))
        _ENV_TIPS = {
            "python": _t("env_python_tip"), "node": _t("env_node_tip"),
            "npm":    _t("env_npm_tip"),    "snyk": _t("env_snyk_tip"),
            "auth":   _t("env_auth_tip"),
        }
        self._check_rows: dict[str, dict] = {}
        for key, name in [("python","Python ≥ 3.9"),("node","Node.js"),
                          ("npm","npm"),("snyk","Snyk CLI"),
                          ("auth",_t("env_auth_row"))]:
            row = tk.Frame(env_card, bg=T["panel_bg"]); row.pack(fill="x", pady=3)
            status = tk.Label(row, text="●", font=(_FUI, 14, "bold"),
                              bg=T["panel_bg"], fg=T["muted"], width=2)
            status.pack(side="left"); _Tooltip(status, _ENV_TIPS.get(key, ""))
            name_lbl = self._lbl(row, name, size=11, bold=True, width=18, anchor="w")
            name_lbl.pack(side="left"); _Tooltip(name_lbl, _ENV_TIPS.get(key, ""))
            detail = self._lbl(row, "…", size=10, fg=T["muted"], anchor="w")
            detail.pack(side="left", fill="x", expand=True, padx=(4, 4))
            fix = self._btn(row, "Fix", lambda k=key: self._fix(k), kind="outline")
            fix.pack(side="right"); fix.config(state="disabled")
            _Tooltip(fix, f"{_t('env_fix_tip')} {name}.")
            self._check_rows[key] = {"status": status, "detail": detail, "fix": fix}
        btn_row = tk.Frame(env_card, bg=T["panel_bg"])
        btn_row.pack(fill="x", pady=(10, 0))
        recheck_btn = self._btn(btn_row, _t("recheck"),
                                lambda: self._run_async(self._recheck, label="env check"),
                                kind="outline")
        recheck_btn.pack(side="left")
        _Tooltip(recheck_btn, _t("env_recheck_tip"))
        self._login_btn = self._btn(btn_row, _t("login_snyk"),
                                    lambda: self._run_async(self._do_login, label="snyk auth"),
                                    kind="accent")
        self._login_btn.pack(side="left", padx=(10, 0))
        self._login_btn.config(state="disabled")
        _Tooltip(self._login_btn, _t("env_login_tip"))

    # ── Tab: DAST ─────────────────────────────────────────────────────────────
    def _build_tab_dast(self, parent):
        self._section_header(parent, _t("dast_title"))
        pad = self._scrollable(parent)
        body = self._card(pad, _t("dast_target_card"))
        body.columnconfigure(1, weight=1)

        def gl(text, r, c, tip=""): return self._glabel(body, text, r, c, tip)

        gl(_t("dast_url_lbl"), 0, 0, _t("dast_url_tip"))
        self._gentry(body, self._dast_url_var, 0, 1, "e.g. https://staging.myapp.com", span=3)
        gl(_t("dast_auth_lbl"), 1, 0, _t("dast_auth_tip"))
        ac = ttk.Combobox(body, textvariable=self._dast_auth_var,
                          values=["none","basic","bearer","cookie","header","form","selenium"],
                          state="readonly", width=12)
        ac.grid(row=1, column=1, sticky="w", pady=3)
        def _on_dast_auth_change(_evt=None):
            self._refresh_dast_creds(); self._refresh_dast_sel_card()
        ac.bind("<<ComboboxSelected>>", _on_dast_auth_change)
        gl(_t("dast_profile_lbl"), 2, 0, _t("dast_profile_tip"))
        pc = ttk.Combobox(body, textvariable=self._dast_profile_var,
                          values=["passive","active"], state="readonly", width=10)
        pc.grid(row=2, column=1, sticky="w", pady=3, padx=(0, 4))
        self._dast_cred_frame = tk.Frame(body, bg=T["panel_bg"])
        self._dast_cred_frame.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(4, 0))
        self._dast_cred_frame.columnconfigure(1, weight=1)
        scope = tk.Frame(body, bg=T["panel_bg"])
        scope.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        self._spin(scope, _t("dast_max_pages_lbl"), self._dast_pages_var, 1, 500,
                   _t("dast_max_pages_tip"), width=5, padx=(0, 14))
        for text, var, tip in [
            ("Include subdomains", self._dast_subs_var,    _t("dast_subdomains_tip")),
            ("Verify TLS",         self._dast_tls_var,     _t("dast_tls_tip")),
            ("Auto re-login",      self._dast_relogin_var, _t("dast_relogin_tip")),
        ]:
            cb = ttk.Checkbutton(scope, text=text, variable=var)
            cb.pack(side="left", padx=(0, 14)); _Tooltip(cb, tip)
        adv = tk.Frame(body, bg=T["panel_bg"])
        adv.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(6, 0))
        adv.columnconfigure(1, weight=2); adv.columnconfigure(3, weight=1)
        self._lbl(adv, _t("dast_exclude_lbl"), size=10, fg=T["muted"]
                  ).grid(row=0, column=0, sticky="w", padx=(0, 6))
        self._gentry(adv, self._dast_exclude_var, 0, 1, _t("dast_exclude_tip"), span=3)
        rps_row = tk.Frame(body, bg=T["panel_bg"])
        rps_row.grid(row=6, column=0, columnspan=4, sticky="ew", pady=(4, 0))
        self._spin(rps_row, _t("dast_rate_lbl"), self._dast_rps_var, 0.5, 100,
                   _t("dast_rate_tip"), inc=0.5, padx=(0, 16))
        self._spin(rps_row, _t("dast_workers_lbl"), self._dast_workers_var, 1, 16,
                   _t("dast_workers_tip"), width=4, padx=(0, 16))
        self._lbl(rps_row, _t("dast_proxy_lbl"), size=10,
                  fg=T["muted"]).pack(side="left", padx=(0, 4))
        px_e = ttk.Entry(rps_row, textvariable=self._dast_proxy_var, width=28)
        px_e.pack(side="left"); _Tooltip(px_e, _t("dast_proxy_tip"))

        sel_card = self._card(pad, _t("dast_sel_card"), pady=(0, 14))
        sel_card.columnconfigure(1, weight=1)
        self._lbl(sel_card, _t("dast_browser_lbl"), size=10,
                  fg=T["muted"]).grid(row=1, column=0, sticky="e", padx=(0, 6))

        # Only list browsers that are actually installed on this machine.
        labels = self._refresh_browser_catalog()
        sel_browser_cb = ttk.Combobox(sel_card,
                                      textvariable=self._dast_browser_label_var,
                                      values=labels, state="readonly", width=18)
        sel_browser_cb.grid(row=1, column=1, sticky="w")
        self._dast_browser_cb = sel_browser_cb
        _Tooltip(sel_browser_cb, _t("dast_browser_tip"))

        def _on_browser_pick(_=None):
            key = self._browser_label_key.get(
                self._dast_browser_label_var.get())
            if key:
                self._dast_browser_var.set(key)
        sel_browser_cb.bind("<<ComboboxSelected>>", _on_browser_pick)
        sel_opts = tk.Frame(sel_card, bg=T["panel_bg"])
        sel_opts.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(4, 0))
        cb_hl = ttk.Checkbutton(sel_opts, text="Headless", variable=self._dast_headless_var)
        cb_hl.pack(side="left", padx=(0, 16)); _Tooltip(cb_hl, _t("dast_headless_tip"))
        self._spin(sel_opts, _t("dast_login_timeout_lbl"), self._dast_selwait_var, 1, 180,
                   _t("dast_login_timeout_tip"), width=5, padx=(0, 16))

        macro_row = tk.Frame(sel_card, bg=T["panel_bg"])
        macro_row.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        tk.Frame(macro_row, bg=T["border"], height=1).pack(fill="x", pady=(0, 8))
        self._lbl(macro_row, "MACROS", size=9, fg=T["muted"], bold=True).pack(anchor="w")
        macro_btns = tk.Frame(macro_row, bg=T["panel_bg"])
        macro_btns.pack(fill="x", pady=(4, 0))
        self._macro_recorded = {"login": False, "logout": False}
        # Checkmark labels — updated after each successful record/load
        self._macro_check_vars = {
            "login":  tk.StringVar(value=""),
            "logout": tk.StringVar(value=""),
        }

        def _refresh_macro_ui():
            """Update checkmark labels and logout button state."""
            for flag, var in self._macro_check_vars.items():
                var.set("  ✔" if self._macro_recorded[flag] else "")
            # Logout button only enabled once login is recorded
            lo_btn = getattr(self, "_macro_logout_btn", None)
            if lo_btn:
                lo_btn.config(state="normal" if self._macro_recorded["login"] else "disabled")

        def _macro_popup(flag, title, icon, desc, record_fn, save_fn, load_fn,
                         rec_tip, save_tip, load_tip):
            popup = self._create_popup(title, w_pct=0.38, h_pct=0.30)
            self._popup_hdr(popup, title, icon=icon)
            body2 = tk.Frame(popup, bg=T["bg"], padx=32, pady=20)
            body2.pack(fill="both", expand=True)

            # Status badge — shows ✔ if recorded, else empty
            status_row = tk.Frame(body2, bg=T["bg"]); status_row.pack(fill="x", pady=(0, 4))
            recorded_now = self._macro_recorded[flag]
            badge_var = tk.StringVar(value="✔  Recorded" if recorded_now else "Not recorded")
            badge_fg  = T["ok"] if recorded_now else T["muted"]
            badge_lbl = tk.Label(status_row, textvariable=badge_var,
                                 font=(_FUI, 10, "bold"), bg=T["bg"], fg=badge_fg)
            badge_lbl.pack(side="left")

            tk.Label(body2, text=desc, font=(_FUI, 10), bg=T["bg"], fg=T["muted"],
                     justify="left", wraplength=460, anchor="w").pack(fill="x", pady=(4, 16))
            btn_row = tk.Frame(body2, bg=T["bg"]); btn_row.pack(fill="x")

            def _do_record():
                popup.close()
                ok = record_fn()   # returns True on success, None/False on cancel/error
                if ok:
                    self._macro_recorded[flag] = True
                    _refresh_macro_ui()

            def _do_load():
                popup.close()
                load_fn()
                # load_fn sets cred vars — consider success if login_url is non-empty
                # (for login) or logout_url_re (for logout)
                check_key = ("selenium_login_url" if flag == "login"
                             else "logout_url_re")
                if self._dast_cred_vars.get(check_key, tk.StringVar()).get().strip():
                    self._macro_recorded[flag] = True
                    _refresh_macro_ui()

            def _do_clear():
                """Reset this condition — clears relevant cred vars and mark."""
                _CLEAR_KEYS = {
                    "login":  ["selenium_login_url","selenium_user_selector",
                               "selenium_user_value","selenium_pass_selector",
                               "selenium_pass_value","selenium_submit_selector",
                               "selenium_extra_steps","selenium_macro",
                               "login_success_selector","login_success_text"],
                    "logout": ["logout_url_re","login_success_selector",
                               "login_success_text"],
                }
                for k in _CLEAR_KEYS.get(flag, []):
                    if k in self._dast_cred_vars:
                        self._dast_cred_vars[k].set("")
                self._macro_recorded[flag] = True   # keep login recorded so logout stays unlocked
                self._macro_recorded[flag] = False
                # If clearing login, also reset logout
                if flag == "login":
                    for k in _CLEAR_KEYS["logout"]:
                        if k in self._dast_cred_vars:
                            self._dast_cred_vars[k].set("")
                    self._macro_recorded["logout"] = False
                _refresh_macro_ui()
                self._refresh_dast_creds()
                badge_var.set("Not recorded")
                badge_lbl.config(fg=T["muted"])
                popup.close()

            save_btn = None
            for text, cmd, kind, tip, dx in [
                ("⏺  Record new", _do_record,                         "accent",  rec_tip,  (0, 8)),
                ("💾  Save…",      lambda: (popup.close(), save_fn()), "outline", save_tip, (0, 8)),
                ("📂  Load…",      _do_load,                          "outline", load_tip, (0, 8)),
                ("🗑  Clear",       _do_clear,                         "flat",
                 f"Clear the recorded {flag} condition and reset all its fields.", (0, 0)),
            ]:
                b = self._btn(btn_row, text, cmd, kind=kind)
                b.pack(side="left", padx=dx)
                _Tooltip(b, tip)
                if text.startswith("💾"):
                    save_btn = b
                    if not self._macro_recorded[flag]:
                        b.config(state="disabled")
                if text.startswith("🗑") and not self._macro_recorded[flag]:
                    b.config(state="disabled")

            self._popup_foot(popup, ("Close", popup.close, "flat"))

        # Login macro button + checkmark
        login_wrap = tk.Frame(macro_btns, bg=T["panel_bg"])
        login_wrap.pack(side="left", padx=(0, 4))
        login_args = ("login", "Login Macro", "⏺",
                      "Record a new macro, or save/load a previously recorded one.",
                      self._dast_record_macro, self._dast_save_login_condition,
                      self._dast_load_login_condition,
                      "Opens a real browser and records your login clicks and form inputs.",
                      "Save the recorded login selectors + session-detection fields.\nPasswords are never written to disk.",
                      "Load a previously saved login-condition file.")
        login_btn = self._btn(login_wrap, "⏺  Record Login Condition",
                              lambda a=login_args: _macro_popup(*a), kind="outline")
        login_btn.pack(side="left")
        _Tooltip(login_btn, "Record, save, or load a Selenium login macro.")
        tk.Label(login_wrap, textvariable=self._macro_check_vars["login"],
                 font=(_FUI, 11, "bold"), bg=T["panel_bg"], fg=T["ok"]).pack(side="left")

        # Logout condition button + checkmark (disabled until login is recorded)
        logout_wrap = tk.Frame(macro_btns, bg=T["panel_bg"])
        logout_wrap.pack(side="left", padx=(4, 0))
        logout_args = ("logout", "Logout Condition", "🚪",
                       "Record a logout condition, or save/load a previously recorded one.",
                       self._dast_record_logout, self._dast_save_logout_condition,
                       self._dast_load_logout_condition,
                       "Opens a browser, replays your login, then records the logout state.",
                       "Save the logout URL regex + logged-in selector & text marker.",
                       "Load a saved logout-condition file.")
        logout_btn = self._btn(logout_wrap, "🚪  Record Logout Condition",
                               lambda a=logout_args: _macro_popup(*a), kind="outline")
        logout_btn.pack(side="left")
        logout_btn.config(state="disabled")  # grayed out until login is recorded
        _Tooltip(logout_btn, "Record session-loss detection. Login condition must be recorded first.")
        tk.Label(logout_wrap, textvariable=self._macro_check_vars["logout"],
                 font=(_FUI, 11, "bold"), bg=T["panel_bg"], fg=T["ok"]).pack(side="left")
        self._macro_logout_btn = logout_btn

        prof_row = tk.Frame(pad, bg=T["bg"])
        prof_save_btn = self._btn(prof_row, "💾  Save Profile…",
                                  self._dast_save_profile, kind="flat")
        prof_save_btn.pack(side="left", padx=(0, 8))
        _Tooltip(prof_save_btn, "Save all DAST settings to a JSON file.\nPasswords and tokens are NOT saved.")
        prof_load_btn = self._btn(prof_row, "📂  Load Profile…",
                                  self._dast_load_profile, kind="flat")
        prof_load_btn.pack(side="left")
        _Tooltip(prof_load_btn, "Load a previously saved DAST profile JSON file.")

        self._dast_sel_card = sel_card
        self._dast_prof_row = prof_row
        self._refresh_dast_creds()
        self._refresh_dast_sel_card()

    def _refresh_creds(self, frame, auth_var, cred_vars, *, session_fields=False):
        for w in frame.winfo_children(): w.destroy()
        frame.columnconfigure(1, weight=1)
        kind   = auth_var.get()
        fields = [f for f in self._DAST_AUTH_FIELDS.get(kind, []) if f[0] in cred_vars]
        for r, (key, label, secret) in enumerate(fields):
            self._lbl(frame, label, size=10, fg=T["muted"], anchor="e"
                      ).grid(row=r, column=0, sticky="e", padx=(0, 6), pady=2)
            ttk.Entry(frame, textvariable=cred_vars[key],
                      show="*" if secret else ""
                      ).grid(row=r, column=1, sticky="ew", pady=2)
        if session_fields:
            r0 = len(fields)
            tk.Frame(frame, bg=T["border"], height=1
                     ).grid(row=r0, column=0, columnspan=2,
                            sticky="ew", pady=6); r0 += 1
            self._lbl(frame, "SESSION DETECTION", size=9,
                      fg=T["muted"], bold=True).grid(row=r0, column=0,
                                                     columnspan=2, sticky="w"); r0 += 1
            _SESSION_TIPS = {
                "login_success_selector": "CSS selector present only when logged in.",
                "login_success_text": "Text that appears on the page only when logged in.",
                "logout_url_re": "Regex for logout URL(s) — these pages are SKIPPED.",
            }
            for key, label in self._SESSION_FIELDS:
                lbl = self._lbl(frame, label, size=10, fg=T["muted"], anchor="e")
                lbl.grid(row=r0, column=0, sticky="e", padx=(0, 6), pady=2)
                e = ttk.Entry(frame, textvariable=cred_vars[key])
                e.grid(row=r0, column=1, sticky="ew", pady=2)
                _Tooltip(lbl, _SESSION_TIPS.get(key, ""))
                _Tooltip(e,   _SESSION_TIPS.get(key, ""))
                r0 += 1

    def _refresh_dast_creds(self):
        self._refresh_creds(self._dast_cred_frame, self._dast_auth_var,
                            self._dast_cred_vars, session_fields=True)

    def _refresh_dast_sel_card(self):
        is_sel = (self._dast_auth_var.get() == "selenium")
        outer = self._dast_sel_card.master
        # Always remove prof_row first so it ends up after sel_card
        self._dast_prof_row.pack_forget()
        if is_sel: outer.pack(fill="x", pady=(0, 14))
        else:      outer.pack_forget()
        self._dast_prof_row.pack(fill="x", pady=(6, 12))

    # ── Tab: API ──────────────────────────────────────────────────────────────
    def _build_tab_api(self, parent):
        self._section_header(parent, _t("api_title"))
        pad = self._scrollable(parent)
        body = self._card(pad, _t("api_spec_card"))
        body.columnconfigure(1, weight=1); body.columnconfigure(3, weight=1)

        def gl(text, r, c, tip=""): return self._glabel(body, text, r, c, tip)

        gl(_t("api_spec_lbl"), 0, 0, _t("api_spec_tip"))
        self._gentry(body, self._api_spec_var, 0, 1, span=2)
        self._btn(body, _t("browse"), self._browse_api_spec, kind="flat"
                  ).grid(row=0, column=3, sticky="w", padx=(4, 0))
        gl(_t("api_base_lbl"), 1, 0, _t("api_base_tip"))
        self._gentry(body, self._api_base_var, 1, 1, span=3)
        gl(_t("api_auth_lbl"), 2, 0, _t("api_auth_tip"))
        api_ac = ttk.Combobox(body, textvariable=self._api_auth_var,
                              values=["none","basic","bearer","cookie","header"],
                              state="readonly", width=10)
        api_ac.grid(row=2, column=1, sticky="w", pady=3)
        api_ac.bind("<<ComboboxSelected>>", lambda _: self._refresh_api_creds())
        _Tooltip(api_ac, _t("api_auth_tip"))
        gl(_t("api_profile_lbl"), 3, 0, _t("api_profile_tip"))
        api_pc = ttk.Combobox(body, textvariable=self._api_profile_var,
                              values=["passive","active"], state="readonly", width=10)
        api_pc.grid(row=3, column=1, sticky="w", pady=3)
        _Tooltip(api_pc, _t("api_profile_tip"))
        self._api_cred_frame = tk.Frame(body, bg=T["panel_bg"])
        self._api_cred_frame.grid(row=4, column=0, columnspan=4,
                                   sticky="ew", pady=(4, 0))
        self._api_cred_frame.columnconfigure(1, weight=1)
        scope = tk.Frame(body, bg=T["panel_bg"])
        scope.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        self._spin(scope, _t("api_max_ep_lbl"), self._api_pages_var, 1, 1000,
                   _t("api_max_ep_tip"), padx=(0, 14))
        cb_tls = ttk.Checkbutton(scope, text="Verify TLS", variable=self._api_tls_var)
        cb_tls.pack(side="left", padx=(0, 14)); _Tooltip(cb_tls, _t("api_tls_tip"))
        self._spin(scope, _t("dast_rate_lbl"), self._api_rps_var, 0.5, 100,
                   _t("dast_rate_tip"), inc=0.5)
        self._lbl(scope, _t("dast_workers_lbl"), size=10,
                  fg=T["muted"]).pack(side="left", padx=(14, 4))
        self._spin(scope, "", self._api_workers_var, 1, 16,
                   _t("dast_workers_tip"), width=4)
        adv = tk.Frame(body, bg=T["panel_bg"])
        adv.grid(row=6, column=0, columnspan=4, sticky="ew", pady=(6, 0))
        adv.columnconfigure(1, weight=2); adv.columnconfigure(4, weight=1)
        self._lbl(adv, _t("api_exclude_lbl"), size=10,
                  fg=T["muted"]).grid(row=0, column=0, sticky="w", padx=(0, 6))
        self._gentry(adv, self._api_exclude_var, 0, 1, _t("api_exclude_tip"), span=2)
        self._lbl(adv, _t("api_proxy_lbl"), size=10,
                  fg=T["muted"]).grid(row=0, column=3, sticky="w", padx=(8, 6))
        self._gentry(adv, self._api_proxy_var, 0, 4, _t("api_proxy_tip"))

        conv_card = self._card(pad, _t("api_conv_card"), pady=(0, 14))
        btn_row_conv = tk.Frame(conv_card, bg=T["panel_bg"])
        btn_row_conv.pack(fill="x", pady=(0, 6))
        self._btn(btn_row_conv, _t("api_preview_btn"),
                  self._api_preview_spec, kind="accent").pack(side="left")
        self._btn(btn_row_conv, _t("api_import_btn"),
                  self._api_import_popup, kind="flat").pack(side="left", padx=(8, 0))
        self._btn(btn_row_conv, "💾 Export…",
                  self._api_export_popup, kind="flat").pack(side="left", padx=(8, 0))

        tree_wrap = tk.Frame(conv_card, bg=T["panel_bg"])
        tree_wrap.pack(fill="both", expand=True)
        self._ep_tree = _make_tree(tree_wrap, ("method","url","secured","body"),
                                   [("Method",70),("Endpoint URL",480),
                                    ("Auth req.",70),("Body type",120)], height=10)
        self._ep_count_lbl = self._lbl(conv_card, "", size=10, fg=T["muted"])
        self._ep_count_lbl.pack(anchor="w", pady=(4, 0))
        self._refresh_api_creds()

    def _refresh_api_creds(self):
        self._refresh_creds(self._api_cred_frame, self._api_auth_var,
                            self._api_cred_vars)

    def _browse_api_spec(self):
        p = filedialog.askopenfilename(
            title="Choose API spec",
            filetypes=[("Spec files","*.json *.yaml *.yml"),("All","*.*")])
        if p: self._api_spec_var.set(p)

    # ── Shared import helper ──────────────────────────────────────────────────
    def _api_load_spec_file(self, title: str, filetypes: list, log_label: str):
        """Open a file dialog, set the spec path, log it, and trigger preview."""
        p = filedialog.askopenfilename(title=title, filetypes=filetypes)
        if p:
            self._api_spec_var.set(p)
            self._emit_log(f"[api] {log_label} loaded: {p}")
            self._api_preview_spec()

    # Kept as named aliases so any external/call-site reference still works.
    def _api_import_postman(self):
        self._api_load_spec_file(
            "Import Postman Collection",
            [("Postman collection", "*.json"), ("All", "*.*")],
            "Postman collection")

    def _api_import_openapi(self):
        self._api_load_spec_file(
            "Import OpenAPI / Swagger spec",
            [("OpenAPI/Swagger", "*.json *.yaml *.yml"), ("All", "*.*")],
            "OpenAPI/Swagger spec")

    def _api_import_popup(self):
        """Popup to choose import type (Postman or Swagger/OpenAPI)."""
        popup = self._create_popup("Import spec", w_pct=0.30, h_pct=0.22)
        self._popup_hdr(popup, "Import spec", icon="📥")
        body = tk.Frame(popup, bg=T["bg"], padx=32, pady=20)
        body.pack(fill="both", expand=True)

        def _pick(kind):
            popup.close()
            if kind == "postman":
                self._api_import_postman()
            else:
                self._api_import_openapi()

        btn_row = tk.Frame(body, bg=T["bg"])
        btn_row.pack(fill="x")
        self._btn(btn_row, "📦  Postman Collection",
                  lambda: _pick("postman"), kind="accent").pack(side="left", padx=(0, 8))
        self._btn(btn_row, "📄  Swagger / OpenAPI",
                  lambda: _pick("openapi"), kind="flat").pack(side="left")

        self._popup_foot(popup, ("Cancel", popup.close, "flat"))

    def _api_export_popup(self):
        """Popup to choose export format then save endpoints."""
        rows = self._ep_tree.get_children()
        if not rows:
            self._show_warn_popup("Export endpoints",
                "No endpoints to export — run 🔍 Preview first.")
            return

        ops = [{"method": self._ep_tree.set(iid, "method"),
                "url":    self._ep_tree.set(iid, "url"),
                "secured":self._ep_tree.set(iid, "secured"),
                "body":   self._ep_tree.set(iid, "body")} for iid in rows]

        popup = self._create_popup("Export endpoints", w_pct=0.26, h_pct=0.34)
        self._popup_hdr(popup, "Export endpoints", icon="💾")
        body = tk.Frame(popup, bg=T["bg"], padx=32, pady=20)
        body.pack(fill="both", expand=True)

        tk.Label(body, text="Choose format:", font=(_FUI, 10),
                 bg=T["bg"], fg=T["muted"]).pack(anchor="w", pady=(0, 10))

        fmt_var = tk.StringVar(value="CSV")
        for fmt in ("CSV", "JSON", "YAML", "Postman v2.1"):
            tk.Radiobutton(body, text=fmt, variable=fmt_var, value=fmt,
                           bg=T["bg"], fg=T["text"], selectcolor=T["panel_bg"],
                           activeforeground=T["accent"], activebackground=T["bg"],
                           font=(_FUI, 10)).pack(anchor="w", pady=2)

        def _do_export():
            fmt = fmt_var.get()
            popup.close()
            self._api_export_converted_with(ops, fmt)

        self._popup_foot(popup,
                         ("Cancel", popup.close, "flat"),
                         ("💾  Export", _do_export, "accent"))

    def _api_preview_spec(self):
        src = self._api_spec_var.get().strip()
        if not src:
            self._show_warn_popup("Preview", "Set a Spec URL or file path first."); return
        def _load_and_render():
            cfg = self._collect_api_cfg()
            opener, _, hdrs = _make_opener(cfg)
            spec = _api_load_spec(opener, hdrs, cfg, self._emit_log)
            if not spec or not isinstance(spec, dict):
                self._event_queue.put(("log","[api-preview] could not load or parse spec."))
                return
            if "item" in spec and "paths" not in spec: fmt = "Postman Collection"
            elif spec.get("openapi","").startswith("3"): fmt = f"OpenAPI {spec.get('openapi','3.x')}"
            elif spec.get("swagger","").startswith("2"): fmt = f"Swagger {spec.get('swagger','2.x')}"
            else: fmt = "Unknown format"
            base = _api_base_url(spec, cfg, src)
            ops  = _api_operations(spec, base or "https://example.com", src)
            self._event_queue.put(("api_preview", (fmt, ops, len(ops))))
        self._run_async(_load_and_render, label="spec preview")

    def _api_export_converted(self):
        """Legacy entry point — now delegates to popup flow."""
        self._api_export_popup()

    def _api_export_converted_with(self, ops, fmt):
        """Perform the actual export given a list of endpoint dicts and a format string."""
        if fmt == "CSV":
            path = filedialog.asksaveasfilename(title="Export endpoints as CSV",
                defaultextension=".csv", initialfile="endpoints.csv",
                filetypes=[("CSV","*.csv"),("All","*.*")])
            if not path: return
            import csv
            with open(path,"w",newline="",encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["method","url","secured","body"])
                w.writeheader(); w.writerows(ops)
        elif fmt == "JSON":
            path = filedialog.asksaveasfilename(title="Export endpoints as JSON",
                defaultextension=".json", initialfile="endpoints.json",
                filetypes=[("JSON","*.json"),("All","*.*")])
            if not path: return
            Path(path).write_text(json.dumps(ops, indent=2), encoding="utf-8")
        elif fmt == "YAML":
            path = filedialog.asksaveasfilename(title="Export endpoints as YAML",
                defaultextension=".yaml", initialfile="endpoints.yaml",
                filetypes=[("YAML","*.yaml *.yml"),("All","*.*")])
            if not path: return
            lines = ["endpoints:\n"]
            for op in ops:
                lines += [f"  - method: {op['method']}\n",
                          f"    url: '{op['url']}'\n",
                          f"    secured: '{op['secured']}'\n",
                          f"    body: '{op['body']}'\n"]
            Path(path).write_text("".join(lines), encoding="utf-8")
        elif fmt == "Postman v2.1":
            path = filedialog.asksaveasfilename(
                title="Export as Postman Collection v2.1",
                defaultextension=".json", initialfile="endpoints_postman.json",
                filetypes=[("JSON / Postman","*.json"),("All","*.*")])
            if not path: return
            items = []
            for op in ops:
                url_parts = op["url"].split("://",1)
                raw_url = op["url"]
                items.append({"name": f"{op['method']} {raw_url}",
                              "request": {"method": op["method"], "header": [],
                                          "url": {"raw": raw_url,
                                                  "protocol": url_parts[0] if len(url_parts)>1 else "https",
                                                  "host": (url_parts[1].split("/")[0].split(".") if len(url_parts)>1 else []),
                                                  "path": (url_parts[1].split("/")[1:] if len(url_parts)>1 else [])},
                                          "description": f"Auth required: {op['secured']}  Body type: {op['body']}"},
                              "response": []})
            collection = {"info": {"name":"Exported Endpoints",
                                   "schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
                          "item": items}
            Path(path).write_text(json.dumps(collection, indent=2), encoding="utf-8")
        else:
            self._show_warn_popup("Export endpoints", f"Unknown format: {fmt}"); return
        self._log_line(f"[api-export] {fmt} → {path}")
        self._show_info_popup("Export complete", f"Saved {len(ops)} endpoint(s) to:\n{path}")

    # ── Tab: Secrets (git-secrets) ────────────────────────────────────────────
    def _build_tab_secrets(self, parent):
        self._section_header(parent, "🔑  Secret Scanning  (git-secrets)")
        pad = self._scrollable(parent)

        info = self._card(pad, "ENGINE")
        st = _GIT_SECRETS_STATUS or {}
        if st.get("method") == "git-secrets" and st.get("available"):
            eng_txt = f"git-secrets ready ({st.get('note','')}) + built-in patterns"
            eng_fg = T["ok"]
        else:
            eng_txt = "Built-in pattern engine (git-secrets download unavailable)"
            eng_fg = T["muted"]
        self._secrets_engine_lbl = self._lbl(info, eng_txt, size=10, fg=eng_fg)
        self._secrets_engine_lbl.pack(anchor="w")
        self._lbl(info, "Scans source files for hard-coded credentials: AWS keys, "
                  "private keys, API tokens, passwords in URLs and more. Results "
                  "are written to a separate secrets.html report.",
                  size=10, fg=T["muted"], justify="left",
                  wraplength=760).pack(anchor="w", pady=(4, 0))

        # Folder row (reuses the scan target var).
        fold = self._card(pad, "TARGET FOLDER")
        row = tk.Frame(fold, bg=T["panel_bg"]); row.pack(fill="x")
        self._lbl(row, "📂 Folder to scan:", size=10, fg=T["muted"],
                  width=16, anchor="w").pack(side="left")
        self._lbl(row, "", size=10, textvariable=self._target_var,
                  anchor="w").pack(side="left", fill="x", expand=True)
        def _browse():
            d = filedialog.askdirectory(title="Choose folder for secret scan",
                                        initialdir=self._target_var.get() or str(SCRIPT_DIR))
            if d: self._target_var.set(d)
        self._btn(row, _t("browse"), _browse, kind="flat").pack(side="right")

        act = tk.Frame(pad, bg=T["bg"]); act.pack(fill="x", pady=(2, 8))
        self._secrets_run_btn = self._btn(act, "🔑  Run secret scan",
                                          self._start_secrets_scan, kind="accent")
        self._secrets_run_btn.pack(side="left")
        self._secrets_open_btn = self._btn(act, "🌐 Open secrets report",
                                           self._open_secrets_report, kind="outline")
        self._secrets_open_btn.pack(side="left", padx=(8, 0))
        self._secrets_open_btn.config(state="disabled")
        self._secrets_count_lbl = self._lbl(act, "", size=10, fg=T["muted"], bg=T["bg"])
        self._secrets_count_lbl.pack(side="left", padx=(12, 0))

        res_card = self._card(pad, "FINDINGS", pady=(0, 0))
        tree_frame = tk.Frame(res_card, bg=T["panel_bg"])
        tree_frame.pack(fill="both", expand=True)
        cols = ("sev", "type", "file", "line", "secret")
        self._secrets_tree = _make_tree(tree_frame, cols, [
            ("Severity", 90), ("Type", 200), ("File", 360),
            ("Line", 60), ("Secret (redacted)", 260)], height=14)

    def _start_secrets_scan(self):
        if self._secrets_busy:
            self._log_line("[secrets] a scan is already running"); return
        target = Path(self._target_var.get()).resolve()
        if not target.exists() or not target.is_dir():
            self._show_warn_popup("Secret scan", f"Folder not found:\n{target}")
            return
        self._secrets_busy = True
        self._secrets_run_btn.config(state="disabled")
        self._secrets_count_lbl.config(text="Scanning…")
        for iid in self._secrets_tree.get_children():
            self._secrets_tree.delete(iid)
        self._run_async(self._secrets_scan, label="secret scan")

    def _secrets_scan(self):
        target = Path(self._target_var.get()).resolve()
        reports_root = Path(self._reports_var.get()).resolve()
        out_dir = reports_root / f"secrets_{_ts()}"
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            result = scan_path(target, self._emit_log,
                               cancel=self._cancel_evt,
                               git_secrets_status=_GIT_SECRETS_STATUS)
            html = write_secrets_report(result, out_dir)
            self._emit_log(f"[secrets] report → {html}")
            # Persist to cumulative state store
            state = getattr(self, "_scan_state", None)
            if state and result:
                try:
                    state.save_kind("secrets", result, target=str(target), mode="secrets")
                    self._emit_log("[state] secrets result persisted to cumulative store")
                except Exception as e:
                    self._emit_log(f"[state] could not save secrets: {e!r}")
            self._event_queue.put(("secrets", (result, str(html))))
        except Exception as e:
            self._emit_log(f"[secrets] scan failed: {e!r}")
            self._event_queue.put(("secrets", (None, None)))

    def _open_secrets_report(self):
        if self._last_secrets_html and Path(self._last_secrets_html).exists():
            webbrowser.open(Path(self._last_secrets_html).as_uri())
        else:
            self._show_info_popup("Secrets report", "Run a secret scan first.")

    # ── Tab: Reports ──────────────────────────────────────────────────────────
    def _build_tab_reports(self, parent):
        self._section_header(parent, _t("reports_title"))
        pad = self._scrollable(parent)
        top_row = tk.Frame(pad, bg=T["bg"]); top_row.pack(fill="x", pady=(0, 12))
        self._btn(top_row, _t("open_viewer"),
                  lambda: ReportsViewer(self, Path(self._reports_var.get()).resolve()),
                  kind="accent").pack(side="left")
        self._btn(top_row, _t("open_report"), self._open_last,
                  kind="outline").pack(side="left", padx=(8, 0))
        self._btn(top_row, _t("export_csv"),
                  self._export_last_csv, kind="flat").pack(side="left", padx=(8, 0))
        self._btn(top_row, "🩹 Remediation history",
                  self._open_remediation_history, kind="flat").pack(side="left", padx=(8, 0))
        rec_card = self._card(pad, _t("recent_scans"), pady=(0, 0))
        tree_frame = tk.Frame(rec_card, bg=T["panel_bg"])
        tree_frame.pack(fill="both", expand=True)
        cols = ("when","mode","total","crit","high","med","low","target")
        self._rep_tree = _make_tree(tree_frame, cols,
                                    [("Generated",150),("Mode",80),("Total",55),
                                     ("Crit",45),("High",45),("Med",45),
                                     ("Low",45),("Target",300)], height=12)
        self._rep_tree.bind("<Double-1>", lambda _: self._open_rep_tree_sel())
        self._refresh_rep_tree()

    @staticmethod
    def _list_report_dirs(root: Path, limit: int = 0) -> list[Path]:
        if not root.exists(): return []
        try:
            items = sorted(
                [p for p in root.iterdir()
                 if p.is_dir() and p.name.startswith("report_")],
                key=lambda p: p.stat().st_mtime, reverse=True)
            return items[:limit] if limit else items
        except OSError: return []

    def _refresh_recent(self):
        if not hasattr(self, "_recent_lb"): return
        self._recent_lb.delete(0, "end")
        root = Path(self._reports_var.get())
        items = self._list_report_dirs(root, limit=6)
        self._recent_paths = items
        if not items:
            self._recent_lb.insert("end", _t("no_reports_yet")); return
        for p in items: self._recent_lb.insert("end", p.name)

    def _refresh_rep_tree(self):
        if not hasattr(self, "_rep_tree"): return
        for iid in self._rep_tree.get_children(): self._rep_tree.delete(iid)
        for d in self._list_report_dirs(Path(self._reports_var.get()), limit=50):
            _fill_tree_row(self._rep_tree, d)

    def _open_rep_tree_sel(self):
        sel = self._rep_tree.selection()
        if not sel: return
        html = Path(sel[0]) / "report.html"
        if html.exists(): webbrowser.open(html.as_uri())

    def _open_remediation_history(self):
        root = Path(self._reports_var.get()).resolve()
        try:
            hist = load_history(root)
            if not hist.get("scans") and not hist.get("actions"):
                self._show_info_popup(
                    "Remediation history",
                    "No history yet. Run a scan first — each scan is recorded and "
                    "compared against the previous one to track remediations.")
                return
            out = render_remediation_history(root)
            self._log_line(f"[history] {out}")
            webbrowser.open(out.as_uri())
        except Exception as e:
            self._show_error_popup("Remediation history", f"Could not build:\n{e!r}")

    # ── Tab: Apps (Application Inventory) ─────────────────────────────────────
    def _build_tab_apps(self, parent):
        """Build the Application Inventory tab using the app_inventory module."""
        from app_inventory import AppInventoryTab
        self._inv_tab = AppInventoryTab(
            parent=parent,
            master=self,
            store=self._inv_store,
            on_load_app=self._load_app_profile,
        )

    def _load_app_profile(self, app: dict) -> None:
        """
        Called by AppInventoryTab when the user clicks '▶ Load into Scanner'.
        Pushes the app's scan config into the main scanner variables.
        """
        self._active_app = app
        # Target folder
        if app.get("target_path"):
            self._target_var.set(app["target_path"])
        # DAST URL
        if app.get("dast_url"):
            self._dast_url_var.set(app["dast_url"])
        # API Spec
        if app.get("api_spec"):
            self._api_spec_var.set(app["api_spec"])
        # Scan stages
        for k, var in self._scan_vars.items():
            var.set(k in app.get("scan_stages", ["sca", "code"]))
        self._refresh_scan_btn()
        # Update the active-app banner on the Scan tab
        lbl = getattr(self, "_active_app_lbl", None)
        if lbl:
            try:
                tier  = app.get("risk_tier", "None")
                from app_inventory import _RISK_COLORS_LIGHT
                colour = _RISK_COLORS_LIGHT.get(tier, T["accent"])
                lbl.config(
                    text=f"{app['name']}  ·  {app.get('criticality','')}  ·  "
                         f"Risk: {tier}  ·  "
                         f"C:{app.get('vuln_critical',0)} H:{app.get('vuln_high',0)} "
                         f"M:{app.get('vuln_medium',0)} L:{app.get('vuln_low',0)}",
                    fg=colour)
            except Exception:
                lbl.config(text=app.get("name", ""), fg=T["accent"])
        # Switch to Scan tab and show confirmation
        self._show_tab("scan")
        self._show_info_popup(
            "App Profile Loaded",
            f"Profile '{app['name']}' is now active.\n\n"
            f"Target: {app.get('target_path') or '(not set)'}\n"
            f"DAST URL: {app.get('dast_url') or '(not set)'}\n"
            f"API Spec: {app.get('api_spec') or '(not set)'}\n"
            f"Stages: {', '.join(app.get('scan_stages', []))}\n\n"
            "Scan results will be recorded in the app's inventory record."
        )

    # ── Tab: Settings ─────────────────────────────────────────────────────────
    def _build_tab_settings(self, parent):
        self._section_header(parent, _t("settings_title"))
        pad = self._scrollable(parent)
        rep_card = self._card(pad, _t("sett_reports_folder_card"), pady=(0, 14))
        fr = tk.Frame(rep_card, bg=T["panel_bg"]); fr.pack(fill="x")
        self._sett_reports_entry = ttk.Entry(fr, textvariable=self._reports_var)
        self._sett_reports_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        def _browse_rep():
            d = filedialog.askdirectory(title="Select reports folder",
                                        initialdir=self._reports_var.get() or str(SCRIPT_DIR))
            if d: self._reports_var.set(d); self._reports_root = Path(d)
        self._btn(fr, "Browse…", _browse_rep, kind="flat").pack(side="left")
        def _open_reports_folder():
            _open_path(self._reports_root)
        self._btn(fr, "📁", _open_reports_folder, kind="flat").pack(side="left", padx=(6, 0))

        lt_row = tk.Frame(pad, bg=T["bg"]); lt_row.pack(fill="x", pady=(0, 14))
        def _radio_row(card, label, var, options, command=None):
            row = tk.Frame(card, bg=T["panel_bg"]); row.pack(fill="x")
            self._lbl(row, label, size=11).pack(side="left", padx=(0, 10))
            for value, text in options:
                tk.Radiobutton(row, text=text, variable=var, value=value,
                               font=(_FUI, 11), bg=T["panel_bg"], fg=T["text"],
                               activebackground=T["card_hover"],
                               selectcolor=T["surface2"],
                               command=command,
                               cursor="hand2").pack(side="left", padx=(0, 16))
        lang_card = self._side_card(lt_row, _t("sett_lang_card"), padx=(0, 6))
        self._sett_lang_var = tk.StringVar(value=self._lang)
        def _on_lang_change():
            global _current_lang
            self._lang = self._sett_lang_var.get()
            _current_lang = self._lang
            self._save_settings()
            self._rebuild_ui()
        _radio_row(lang_card, _t("sett_interface_lang"), self._sett_lang_var,
                   [("en","🇬🇧  English"),("es","🇲🇽  Español")], command=_on_lang_change)
        theme_card = self._side_card(lt_row, _t("sett_theme_card"))
        self._sett_dark_var = tk.BooleanVar(value=self._dark_mode)
        def _on_theme_change():
            self._dark_mode = bool(self._sett_dark_var.get())
            self._apply_theme_to_app()
            self._save_settings()
        _radio_row(theme_card, _t("sett_color_theme"), self._sett_dark_var,
                   [(False,"☀  Light"),(True,"🌙  Dark")], command=_on_theme_change)

        misc_card = self._card(pad, _t("sett_misc_card"), pady=(0, 14))
        self._sett_auto_open_var   = tk.BooleanVar(value=self._auto_open)
        self._sett_confirm_del_var = tk.BooleanVar(value=self._confirm_del)
        self._sett_log_lines_var   = tk.IntVar(value=self._max_log_lines)
        def _on_misc_change(*_):
            self._auto_open    = bool(self._sett_auto_open_var.get())
            self._confirm_del  = bool(self._sett_confirm_del_var.get())
            self._save_settings()
        for text, var, tip in [
            (_t("sett_auto_open_cb"),   self._sett_auto_open_var,
             "Automatically launch the HTML report in the default browser when a scan finishes."),
            (_t("sett_confirm_del_cb"), self._sett_confirm_del_var,
             "Show a confirmation dialog before permanently deleting a report folder."),
        ]:
            row = tk.Frame(misc_card, bg=T["panel_bg"]); row.pack(fill="x", pady=2)
            cb = ttk.Checkbutton(row, text=text, variable=var, command=_on_misc_change)
            cb.pack(side="left"); _Tooltip(cb, tip)
        log_row = tk.Frame(misc_card, bg=T["panel_bg"])
        log_row.pack(fill="x", pady=(8, 0))
        self._lbl(log_row, _t("sett_max_log"), size=10,
                  fg=T["muted"]).pack(side="left", padx=(0, 6))
        def _on_log_lines_change(*_):
            try:
                self._max_log_lines = int(self._sett_log_lines_var.get())
                self._save_settings()
            except Exception: pass
        sp = self._spin(log_row, "", self._sett_log_lines_var, 100, 10000,
                   "Oldest lines are trimmed when this limit is reached.",
                   inc=100, width=7)
        sp.bind("<<Increment>>", _on_log_lines_change)
        sp.bind("<<Decrement>>", _on_log_lines_change)

        # ── Cumulative Scan State card ─────────────────────────────────────────
        state_card = self._card(pad, "📊  CUMULATIVE SCAN STATE", pady=(0, 14))
        self._lbl(state_card,
                  "Each scan type (SCA, SAST, DAST, API, Secrets) is stored independently. "
                  "Every report combines the last run of each type automatically.",
                  size=10, fg=T["muted"], justify="left",
                  wraplength=900).pack(anchor="w", pady=(0, 8))
        self._state_rows: dict[str, dict] = {}
        _kind_labels = [
            ("sca",     "🔍 SCA",      "Last Snyk SCA (dependency) scan"),
            ("code",    "🧬 SAST",     "Last Snyk Code (static analysis) scan"),
            ("dast",    "🌐 DAST",     "Last Dynamic Application Security Test"),
            ("api",     "🔌 API",      "Last API Security scan"),
            ("secrets", "🔑 Secrets",  "Last Secret / Credential scan"),
        ]
        for kind, label, tip in _kind_labels:
            row_f = tk.Frame(state_card, bg=T["panel_bg"]); row_f.pack(fill="x", pady=2)
            tk.Label(row_f, text=label, font=(_FUI, 11, "bold"),
                     bg=T["panel_bg"], fg=T["text"], width=12, anchor="w").pack(side="left")
            ts_lbl = self._lbl(row_f, "—", size=10, fg=T["muted"], anchor="w", width=20)
            ts_lbl.pack(side="left", padx=(4, 0))
            tg_lbl = self._lbl(row_f, "", size=10, fg=T["muted"], anchor="w")
            tg_lbl.pack(side="left", fill="x", expand=True, padx=(8, 0))
            clr_btn = self._btn(row_f, "✕ Clear",
                                lambda k=kind: self._clear_scan_state(k), kind="flat")
            clr_btn.pack(side="right")
            _Tooltip(clr_btn, f"Remove persisted {label} data from the cumulative store.")
            self._state_rows[kind] = {"ts": ts_lbl, "target": tg_lbl}
        state_refresh_btn = self._btn(state_card, "🔄 Refresh status",
                                      self._refresh_state_status, kind="flat")
        state_refresh_btn.pack(anchor="w", pady=(8, 0))
        self._refresh_state_status()

    def _refresh_state_status(self):
        """Refresh the cumulative-state status labels in Settings."""
        state = getattr(self, "_scan_state", None)
        rows  = getattr(self, "_state_rows", {})
        if not state or not rows:
            return
        idx = state.summary()
        for kind, widgets in rows.items():
            meta = idx.get(kind)
            ts_lbl = widgets.get("ts")
            tg_lbl = widgets.get("target")
            if meta and isinstance(meta, dict) and meta.get("ts"):
                ts_text = meta["ts"][:16]
                tg_text = (meta.get("target") or "")[:60]
                if ts_lbl:
                    try: ts_lbl.config(text=ts_text, fg=T["ok"])
                    except Exception: pass
                if tg_lbl:
                    try: tg_lbl.config(text=tg_text)
                    except Exception: pass
            else:
                if ts_lbl:
                    try: ts_lbl.config(text="not yet scanned", fg=T["muted"])
                    except Exception: pass
                if tg_lbl:
                    try: tg_lbl.config(text="")
                    except Exception: pass

    def _clear_scan_state(self, kind: str):
        """Clear one kind from the cumulative state store."""
        state = getattr(self, "_scan_state", None)
        if not state:
            return
        if self._ask_yesno_popup(
                "Clear scan state",
                f"Remove persisted {kind.upper()} data from the cumulative store?\n\n"
                "The next report will not include this scan type until\n"
                "you run a new scan."):
            try:
                state.clear_kind(kind)
                self._emit_log(f"[state] cleared {kind} from cumulative store")
                self._refresh_state_status()
            except Exception as e:
                self._show_error_popup("Clear state", f"Failed:\n{e}")

    def _rebuild_ui(self):
        active = getattr(self, "_active_tab", "scan")
        for child in list(self.winfo_children()):
            try: child.destroy()
            except Exception: pass
        self._ribbon_tabs = {}; self._tab_frames = {}; self._stage_pills = {}
        self._check_rows = {}; self._log_widget = None  # type: ignore
        self._inv_tab = None  # will be recreated by _build_tab_apps
        self._console_visible = False; self._unread_log = 0
        self._setup_styles(); self._build_ui(); self._show_tab(active)
        self.after(100, self._refresh_scan_btn)
        self.after(200, self._refresh_recent)
        self.after(200, self._refresh_rep_tree)
        if self._checks:
            self.after(50, lambda: self._apply_checks(self._checks))

    # ── Scan button state ─────────────────────────────────────────────────────
    def _refresh_scan_btn(self):
        if not hasattr(self, "_scan_btn"): return
        sel = {k for k, v in self._scan_vars.items() if v.get()}
        if not sel:
            self._scan_btn.config(state="disabled")
            if hasattr(self, "_run_icon_btn"):
                self._run_icon_btn.config(state="disabled")
            return
        needs_snyk = bool({"sca","code"} & sel)
        checks     = self._checks or {}
        env_ok     = all((checks.get(k) and checks[k].ok)
                         for k in ("python","node","npm","snyk"))
        auth_ok    = bool(checks.get("auth") and checks["auth"].ok)
        ready      = (not needs_snyk) or (env_ok and auth_ok)
        state = "normal" if ready else "disabled"
        self._scan_btn.config(state=state)
        if hasattr(self, "_run_icon_btn"):
            if ready:
                self._run_icon_btn.config(state="normal",
                    fg=T["accent"], highlightbackground=T["accent"],
                    highlightcolor=T["accent"])
            else:
                self._run_icon_btn.config(state="disabled",
                    fg=T["muted"], highlightbackground=T["muted"],
                    highlightcolor=T["muted"])

    # ── Environment checks ────────────────────────────────────────────────────
    def _recheck(self):
        self._event_queue.put(("checks", {
            "python": check_python(), "node": check_node(),
            "npm":    check_npm(),    "snyk": check_snyk(),
            "auth":   check_auth(),
        }))

    def _apply_checks(self, results: dict[str, CheckResult]):
        self._checks = results
        for key, res in results.items():
            row = self._check_rows.get(key)
            if not row: continue
            row["status"].config(text="●", fg=T["ok"] if res.ok else (
                T["muted"] if not res.detail or res.detail == "…" else T["err"]))
            row["detail"].config(text=res.detail or ("ready" if res.ok else "not configured"))
            row["fix"].config(state="disabled" if (res.ok or not res.fixable) else "normal")
        env_ok  = all(results[k].ok for k in ("python","node","npm","snyk"))
        auth_ok = bool(results["auth"].ok)
        env_tab_btn = self._ribbon_tabs.get("env")
        if env_tab_btn:
            is_active = (self._active_tab == "env")
            fg = T["button_fg"] if is_active else (
                T["err"] if not (env_ok and auth_ok) else T["text"])
            env_tab_btn.config(fg=fg)
        if env_ok and not auth_ok:
            self._login_btn.config(state="normal", text="🔑 Login with Snyk")
        else:
            self._login_btn.config(
                state="disabled",
                text="✓ Logged in" if auth_ok else "🔑 Login with Snyk")
        self._refresh_scan_btn()

    def _fix(self, key: str):
        installers = {
            "node": (install_node, "install node"),
            "npm":  (install_node, "install node/npm"),
            "snyk": (install_snyk, "install snyk"),
        }
        if key in installers:
            fn, label = installers[key]
            self._run_async(lambda f=fn: (f(self._emit_log), self._recheck()),
                            label=label)
        elif key == "auth":
            self._run_async(self._do_login, label="snyk auth")

    # ── Auth ──────────────────────────────────────────────────────────────────
    def _do_login(self):
        if not _which("snyk"):
            self._emit_log("[auth] Snyk CLI missing — install it first."); return
        if self._auth_proc and self._auth_proc.poll() is None:
            self._emit_log("[auth] auth already in progress"); return
        self._auth_proc    = start_snyk_auth(self._emit_log)
        self._auth_deadline = time.time() + AUTH_POLL_TIMEOUT
        self._event_queue.put(("status","Waiting for Snyk auth in browser…"))

    def _tick_auth_poll(self):
        proc = self._auth_proc
        if proc is None: return
        try:
            if proc.stdout and not proc.stdout.closed:
                line = proc.stdout.readline()
                if line: self._log_line(line.rstrip())
        except Exception: pass
        now = time.time()
        if not hasattr(self, "_next_auth_check") or now >= self._next_auth_check:
            self._next_auth_check = now + AUTH_POLL_INTERVAL
            if check_auth().ok:
                self._log_line("[auth] authenticated.")
                try: proc.terminate()
                except Exception: pass
                self._auth_proc = None
                self._recheck(); return
        if proc.poll() is not None:
            self._log_line(f"[auth] snyk auth exited ({proc.returncode})")
            self._auth_proc = None
            self._run_async(self._recheck, label="post-auth recheck"); return
        if now > self._auth_deadline:
            self._log_line("[auth] timeout — cancelling.")
            try: proc.terminate()
            except Exception: pass
            self._auth_proc = None

    # ── Config collectors ─────────────────────────────────────────────────────
    def _on_app_close(self):
        """Scrub runtime-only secrets (recorded password, tokens) before exit so
        they never linger in memory after the window is gone."""
        try:
            for k in ("password", "token", "selenium_pass_value"):
                if k in self._dast_cred_vars:
                    self._dast_cred_vars[k].set("")
            for k in ("password", "token"):
                if k in getattr(self, "_api_cred_vars", {}):
                    self._api_cred_vars[k].set("")
            self._runtime_pass = ""
        except Exception:
            pass
        try: self.destroy()
        except Exception: pass

    def _refresh_browser_catalog(self) -> list[str]:
        """Detect installed browsers and refresh the label↔key maps.

        Returns the list of friendly labels for the combobox. Falls back to a
        Chrome-only list if detection isn't available yet (engine not loaded)."""
        catalog = {}
        try:
            catalog = detect_browsers() or {}
        except Exception:
            try:
                from dast_api import detect_browsers as _db
                catalog = _db() or {}
            except Exception:
                catalog = {}
        if not catalog:   # never leave the dropdown empty
            catalog = {"chrome": {"name": "Google Chrome", "binary": "",
                                  "engine": "chromium"}}
        self._browser_catalog   = catalog
        self._browser_label_key = {info["name"]: key
                                   for key, info in catalog.items()}
        labels = [info["name"] for info in catalog.values()]
        # Keep the current selection valid; otherwise pick the first detected.
        cur_key = self._dast_browser_var.get()
        if cur_key not in catalog:
            cur_key = next(iter(catalog))
            self._dast_browser_var.set(cur_key)
        self._dast_browser_label_var.set(catalog[cur_key]["name"])
        return labels

    def _collect_dast_cfg(self) -> DastConfig:
        v = self._dast_cred_vars; g = lambda k: v[k].get()
        browser_key = self._dast_browser_var.get() or "chrome"
        browser_bin = (self._browser_catalog.get(browser_key, {}) or {}).get("binary", "")
        return DastConfig(
            url=self._dast_url_var.get().strip(),
            auth_type=self._dast_auth_var.get(),
            username=g("username"), password=g("password"), token=g("token"),
            cookie=g("cookie"), header_name=g("header_name"),
            header_value=g("header_value"),
            login_url=g("login_url"), login_data=g("login_data"),
            profile=self._dast_profile_var.get(),
            max_pages=int(self._dast_pages_var.get() or 30),
            verify_tls=bool(self._dast_tls_var.get()),
            include_subdomains=bool(self._dast_subs_var.get()),
            selenium_browser=browser_key,
            selenium_binary=browser_bin,
            selenium_headless=bool(self._dast_headless_var.get()),
            selenium_wait_seconds=int(self._dast_selwait_var.get() or 15),
            selenium_login_url=g("selenium_login_url"),
            selenium_user_selector=g("selenium_user_selector"),
            selenium_user_value=g("selenium_user_value"),
            selenium_pass_selector=g("selenium_pass_selector"),
            selenium_pass_value=g("selenium_pass_value"),
            selenium_submit_selector=g("selenium_submit_selector"),
            selenium_extra_steps=g("selenium_extra_steps"),
            selenium_macro=g("selenium_macro"),
            login_success_selector=g("login_success_selector"),
            login_success_text=g("login_success_text"),
            logout_url_re=g("logout_url_re"),
            auto_relogin=bool(self._dast_relogin_var.get()),
            exclude_re=self._dast_exclude_var.get(),
            rate_limit_rps=float(self._dast_rps_var.get() or 8.0),
            concurrency=int(self._dast_workers_var.get() or 4),
            proxy=self._dast_proxy_var.get())

    def _collect_api_cfg(self) -> ApiConfig:
        v = self._api_cred_vars
        return ApiConfig(
            spec_source=self._api_spec_var.get().strip(),
            base_url=self._api_base_var.get().strip(),
            auth_type=self._api_auth_var.get(),
            username=v["username"].get(),     password=v["password"].get(),
            token=v["token"].get(),           cookie=v["cookie"].get(),
            header_name=v["header_name"].get(), header_value=v["header_value"].get(),
            profile=self._api_profile_var.get(),
            max_endpoints=int(self._api_pages_var.get() or 80),
            verify_tls=bool(self._api_tls_var.get()),
            rate_limit_rps=float(self._api_rps_var.get() or 8.0),
            concurrency=int(self._api_workers_var.get() or 6),
            proxy=self._api_proxy_var.get(),
            exclude_re=self._api_exclude_var.get())

    # ── DAST profile save/load ────────────────────────────────────────────────
    def _dast_save_profile(self):
        cfg  = self._collect_dast_cfg()
        data = {k: v for k, v in cfg.__dict__.items()
                if k not in ("password","token","selenium_pass_value")}
        path = filedialog.asksaveasfilename(
            title="Save DAST profile", defaultextension=".json",
            initialfile="dast_profile.json",
            filetypes=[("DAST profile","*.json"),("All","*.*")])
        if not path: return
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        self._emit_log(f"[dast] profile saved → {path}  (secrets stripped)")

    def _dast_load_profile(self):
        path = filedialog.askopenfilename(
            title="Load DAST profile",
            filetypes=[("DAST profile","*.json"),("All","*.*")])
        if not path: return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as e:
            self._show_error_popup("Load Profile", f"Cannot read file:\n{e}"); return
        _load_map = [
            (self._dast_url_var,"url",str,""),
            (self._dast_auth_var,"auth_type",str,"none"),
            (self._dast_profile_var,"profile",str,"passive"),
            (self._dast_pages_var,"max_pages",int,30),
            (self._dast_subs_var,"include_subdomains",bool,False),
            (self._dast_tls_var,"verify_tls",bool,True),
            (self._dast_relogin_var,"auto_relogin",bool,True),
            (self._dast_browser_var,"selenium_browser",str,"chrome"),
            (self._dast_headless_var,"selenium_headless",bool,True),
            (self._dast_selwait_var,"selenium_wait_seconds",int,15),
            (self._dast_exclude_var,"exclude_re",str,""),
            (self._dast_rps_var,"rate_limit_rps",float,8.0),
            (self._dast_workers_var,"concurrency",int,4),
            (self._dast_proxy_var,"proxy",str,""),
        ]
        for var, key, cast, dflt in _load_map:
            var.set(cast(data.get(key, dflt)))
        # Re-sync the browser dropdown label to the loaded key (re-detect first
        # so a profile saved on another machine still resolves to what's here).
        try:
            self._refresh_browser_catalog()
            if getattr(self, "_dast_browser_cb", None) is not None:
                self._dast_browser_cb.config(
                    values=[i["name"] for i in self._browser_catalog.values()])
            bkey = self._dast_browser_var.get()
            if bkey in self._browser_catalog:
                self._dast_browser_label_var.set(self._browser_catalog[bkey]["name"])
        except Exception:
            pass
        for k, var in self._dast_cred_vars.items():
            var.set(str(data.get(k,"")))
        self._refresh_dast_creds()
        self._emit_log(f"[dast] profile loaded ← {path}")

    # ── Login / logout condition save & load ──────────────────────────────────
    _LOGIN_CONDITION_KEYS = [
        "selenium_login_url","selenium_user_selector","selenium_user_value",
        "selenium_pass_selector","selenium_submit_selector","selenium_extra_steps",
        "selenium_macro","login_success_selector","login_success_text",
    ]
    _LOGOUT_CONDITION_KEYS = ["logout_url_re","login_success_selector","login_success_text"]

    def _dast_save_condition(self, keys, name, initialfile, note=""):
        data = {k: self._dast_cred_vars[k].get()
                for k in keys if k in self._dast_cred_vars}
        # Passwords are NEVER written to disk. selenium_pass_value is already
        # excluded from the key list, but the literal macro may carry the typed
        # password inside a recorded password field — strip those values too.
        if data.get("selenium_macro"):
            try:
                steps = json.loads(data["selenium_macro"])
                for s in steps:
                    if isinstance(s, dict) and s.get("kind") == "field" and (
                            s.get("role") == "password"
                            or s.get("ftype") == "password"):
                        s["value"] = ""        # re-injected at runtime
                data["selenium_macro"] = json.dumps(steps)
            except Exception:
                pass
        path = filedialog.asksaveasfilename(
            title=f"Save {name}", defaultextension=".json", initialfile=initialfile,
            filetypes=[(name.capitalize(),"*.json"),("All","*.*")])
        if not path: return
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        self._emit_log(f"[dast] {name} saved → {path}{note}")

    def _dast_load_condition(self, keys, name):
        path = filedialog.askopenfilename(
            title=f"Load {name}",
            filetypes=[(name.capitalize(),"*.json"),("All","*.*")])
        if not path: return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as e:
            self._show_error_popup(f"Load {name.title()}", f"Cannot read file:\n{e}"); return
        applied = [k for k in keys if k in data and k in self._dast_cred_vars
                   and (self._dast_cred_vars[k].set(str(data[k])) or True)]
        self._refresh_dast_creds()
        self._emit_log(f"[dast] {name} loaded ← {path}  "
                       f"(fields: {', '.join(applied) or 'none'})")

    def _dast_save_login_condition(self):
        self._dast_save_condition(self._LOGIN_CONDITION_KEYS, "login condition",
                                  "dast_login_condition.json",
                                  "  (password value excluded)")
    def _dast_load_login_condition(self):
        self._dast_load_condition(self._LOGIN_CONDITION_KEYS, "login condition")
    def _dast_save_logout_condition(self):
        self._dast_save_condition(self._LOGOUT_CONDITION_KEYS, "logout condition",
                                  "dast_logout_condition.json")
    def _dast_load_logout_condition(self):
        self._dast_load_condition(self._LOGOUT_CONDITION_KEYS, "logout condition")

    # ── Browser-based recorders ───────────────────────────────────────────────
    def _record_in_browser(self, err_title, popup_title, instructions, work,
                           *, w_pct=0.32, h_pct=0.30):
        """Launch browser + show a small evasive floating HUD that stays out of
        the way.  The HUD is NOT modal — the user can freely interact with the
        browser.  It moves to another corner whenever the mouse hovers over it."""
        url = (self._dast_cred_vars["selenium_login_url"].get().strip()
               or self._dast_url_var.get().strip())
        if not url or url == "https://":
            self._show_error_popup(err_title,
                "Set a Target URL or Login page URL first."); return None
        done  = threading.Event()
        result: dict = {}

        # Thread-safe status relay: the worker thread (which runs `work`) must
        # never touch Tk widgets directly. It only writes the latest message
        # into this holder; a poller on the Tk thread (see _poll_status below)
        # copies it onto the HUD label. A plain dict assignment is atomic under
        # the GIL, so no lock is needed.
        status_box: dict = {"msg": None, "shown": None}
        def _emit_status(msg: str):
            status_box["msg"] = msg

        # ── Launch browser immediately in background thread ──────────────────
        driver_ready = threading.Event()

        def runner():
            try:
                drv = _make_driver(self._collect_dast_cfg(),
                                   headless=False, log=self._emit_log)
                result["_driver"] = drv
                driver_ready.set()
                try:
                    work(drv, url, done, result, _emit_status)
                finally:
                    try: drv.quit()
                    except Exception: pass
            except Exception as e:
                result["error"] = repr(e)
                driver_ready.set()
            finally:
                done.set()

        t = threading.Thread(target=runner, daemon=True)
        t.start()

        # ── Build a tiny non-blocking floating HUD ───────────────────────────
        HUD_W, HUD_H = 360, 105
        PADDING      = 14        # px from screen edge
        CORNERS      = ["ne", "nw", "sw", "se"]  # cycle order

        hud = tk.Toplevel(self)
        hud.overrideredirect(True)
        hud.attributes("-topmost", True)
        hud.attributes("-alpha", 0.90)
        hud.resizable(False, False)

        # Corner-cycle state
        hud._corner_idx = [0]   # starts at NE

        def _place_hud(corner: str):
            sw = hud.winfo_screenwidth()
            sh = hud.winfo_screenheight()
            if corner == "ne":
                x, y = sw - HUD_W - PADDING, PADDING
            elif corner == "nw":
                x, y = PADDING, PADDING
            elif corner == "sw":
                x, y = PADDING, sh - HUD_H - PADDING
            else:  # se
                x, y = sw - HUD_W - PADDING, sh - HUD_H - PADDING
            hud.geometry(f"{HUD_W}x{HUD_H}+{x}+{y}")

        def _dodge(event=None):
            """Move to next corner."""
            idx = (hud._corner_idx[0] + 1) % len(CORNERS)
            hud._corner_idx[0] = idx
            _place_hud(CORNERS[idx])

        _place_hud(CORNERS[0])

        # Style — dark card, accent border
        outer = tk.Frame(hud, bg=T["accent"], padx=1, pady=1)
        outer.pack(fill="both", expand=True)
        inner = tk.Frame(outer, bg=T["panel_bg"], padx=10, pady=8)
        inner.pack(fill="both", expand=True)

        tk.Label(inner, text=popup_title, font=(_FUI, 10, "bold"),
                 bg=T["panel_bg"], fg=T["accent"]).pack(anchor="w")

        # Status line — changes once browser is open
        status_var = tk.StringVar(value="⏳  Opening browser…")
        tk.Label(inner, textvariable=status_var, font=(_FUI, 9),
                 bg=T["panel_bg"], fg=T["muted"],
                 wraplength=HUD_W - 24).pack(anchor="w", pady=(2, 4))

        # Hotkey hint (always visible)
        hotkey_lbl = tk.Label(inner,
                              text="Ctrl+Shift+F12  →  capture     Ctrl+Shift+F11  →  cancel",
                              font=(_FUI, 8), bg=T["panel_bg"], fg=T["muted"])
        hotkey_lbl.pack(anchor="w")

        # Bind mouse-enter → dodge on every child widget
        for widget in (hud, outer, inner, hotkey_lbl):
            widget.bind("<Enter>", _dodge, "+")

        cancelled = [False]
        ready     = [False]

        _hotkey_stop   = threading.Event()
        _hotkey_cancel = threading.Event()

        # ── Global hotkey via pynput (works even when browser has focus) ──────
        # Ctrl+Shift+F12 = capture,  Ctrl+Shift+F11 = cancel
        # These combos don't conflict with Chrome / Brave / Firefox.
        def _pynput_listener():
            try:
                from pynput import keyboard as _kb
                _pressed = set()

                def _on_press(key):
                    _pressed.add(key)
                    ctrl  = any(k in _pressed for k in (
                                _kb.Key.ctrl, _kb.Key.ctrl_l, _kb.Key.ctrl_r))
                    shift = any(k in _pressed for k in (
                                _kb.Key.shift, _kb.Key.shift_l, _kb.Key.shift_r))
                    if ctrl and shift:
                        if key == _kb.Key.f12:
                            _hotkey_stop.set()
                        elif key == _kb.Key.f11:
                            _hotkey_cancel.set()

                def _on_release(key):
                    _pressed.discard(key)

                with _kb.Listener(on_press=_on_press,
                                  on_release=_on_release) as lst:
                    while not done.is_set():
                        if done.wait(0.2):
                            break
                    lst.stop()
            except Exception as ex:
                self._emit_log(f"[hotkey] pynput unavailable ({ex!r}) — "
                               "press Ctrl+Shift+F12 while the Scanner window is focused")

        threading.Thread(target=_pynput_listener, daemon=True).start()

        # Fallback binding on Tk root (activates when Scanner window has focus)
        def _on_key_tk(event):
            state = event.state
            ctrl  = bool(state & 0x4)
            shift = bool(state & 0x1)
            if ctrl and shift and event.keysym == "F12":
                _hotkey_stop.set()
            elif ctrl and shift and event.keysym == "F11":
                _hotkey_cancel.set()

        _key_bind_id = self.bind("<KeyPress>", _on_key_tk, "+")
        hud.bind("<KeyPress>", _on_key_tk, "+")

        # Wire hotkey events → flags (polled every 150 ms on the Tk thread)
        def _poll_hotkeys():
            if _hotkey_cancel.is_set():
                cancelled[0] = True
                done.set()
                return
            if _hotkey_stop.is_set() and ready[0]:
                done.set()
                return
            hud.after(150, _poll_hotkeys)

        hud.after(150, _poll_hotkeys)

        # Poll until driver_ready, then update status
        def _poll_ready():
            if driver_ready.is_set():
                if "error" not in result:
                    # Don't stomp on a status the worker has already emitted
                    # (e.g. "Replaying saved login…").
                    if status_box.get("msg") is None:
                        status_var.set("✅  Browser open — interact freely")
                    ready[0] = True
                else:
                    status_var.set("❌  Browser failed")
                return
            hud.after(200, _poll_ready)

        hud.after(200, _poll_ready)

        # Relay worker-thread status messages onto the HUD label (Tk thread).
        def _poll_status():
            m = status_box.get("msg")
            if m is not None and m != status_box.get("shown"):
                status_var.set(m)
                status_box["shown"] = m
            if not (done.is_set() or cancelled[0]):
                hud.after(180, _poll_status)

        hud.after(180, _poll_status)

        # Poll until done, then destroy HUD and remove Tk binding
        def _poll_done():
            if done.is_set() or cancelled[0]:
                try: self.unbind("<KeyPress>", _key_bind_id)
                except Exception: pass
                try: hud.destroy()
                except Exception: pass
                return
            hud.after(300, _poll_done)

        hud.after(300, _poll_done)

        # Block main thread until recording is done
        self.wait_window(hud)
        t.join(timeout=10)

        if cancelled[0] or "error" in result:
            if "error" in result:
                self._show_error_popup(err_title,
                    f"Browser failed:\n{result['error']}")
            return None
        result["_url"] = url
        return result

    def _dast_record_macro(self):
        # Drain-and-accumulate: events live in sessionStorage and are pulled out
        # every poll so the navigation that login triggers can't destroy them.
        def work(driver, url, done, result, set_status=lambda *_: None):
            self._emit_log(f"[macro] opening {url} — log in, then press "
                           "Ctrl+Shift+F12 to capture")
            driver.get(url)
            set_status("✅  Log in normally, then press Ctrl+Shift+F12")
            acc: list = []
            try: driver.execute_script(_MACRO_JS)
            except Exception: pass
            while not done.is_set():
                # (Re-)install listeners — they're wiped on every navigation.
                try: driver.execute_script(
                    "if(!window.__macro_installed){" + _MACRO_JS + "}")
                except Exception: pass
                # Drain whatever has accumulated since the last poll.
                try:
                    chunk = json.loads(driver.execute_script(_MACRO_DRAIN_JS) or "[]")
                    if chunk: acc.extend(chunk)
                except Exception: pass
                if done.wait(0.4): break
            # Final drain after the user hits capture.
            try:
                chunk = json.loads(driver.execute_script(_MACRO_DRAIN_JS) or "[]")
                if chunk: acc.extend(chunk)
            except Exception: pass
            result["macro"] = json.dumps(acc)
            try: result["cookies"] = driver.get_cookies() or []
            except Exception: result["cookies"] = []

        result = self._record_in_browser(
            "Record Login Condition", "⏺ Login Condition",
            [], work, w_pct=0.32, h_pct=0.30)
        if result is None: return False     # cancelled or error — no palomita
        url = result["_url"]
        try: macro = json.loads(result.get("macro") or "[]")
        except Exception: macro = []
        if not isinstance(macro, list): macro = []
        macro = [s for s in macro if isinstance(s, dict)]

        user_sel, user_val, pass_sel, pass_val, submit_sel = \
            self._analyze_login_macro(macro)

        # Build the submit step. A login submitted with Enter (or whose submit
        # button can't be pinned down) is replayed via the form, not a click —
        # this is exactly the case the old recorder failed on.
        submit_extra = None
        if not submit_sel:
            sub = next((s for s in macro if s.get("kind") == "submit"), None)
            ent = next((s for s in macro if s.get("kind") == "enter"), None)
            if sub and sub.get("button"):
                submit_sel = sub["button"]
            elif sub and sub.get("form"):
                submit_extra = {"submit": sub["form"]}
            elif ent and ent.get("form"):
                submit_extra = {"submit": ent["form"]}
            elif ent:
                submit_extra = {"key": "Enter",
                                "selector": ent.get("selector") or pass_sel}

        if user_sel:   self._dast_cred_vars["selenium_user_selector"].set(user_sel)
        if user_val:   self._dast_cred_vars["selenium_user_value"].set(user_val)
        if pass_sel:   self._dast_cred_vars["selenium_pass_selector"].set(pass_sel)
        # Password is kept in the running session only (stripped from every save).
        if pass_val:   self._dast_cred_vars["selenium_pass_value"].set(pass_val)
        self._dast_cred_vars["selenium_submit_selector"].set(submit_sel or "")
        if not self._dast_cred_vars["selenium_login_url"].get():
            self._dast_cred_vars["selenium_login_url"].set(url)

        # Extra steps = other meaningful fields/clicks the user performed, minus
        # the user/pass/submit we already handle and minus anything that looks
        # like a logout (so replay never logs us out by accident).
        _LOGOUT_RE = _re.compile(
            r"(?i)(logout|log[\s_-]?out|sign[\s_-]?out|signoff|cerrar[\s_-]?sesi[oó]n|salir)")
        extras: list = []
        for s in macro:
            kind = s.get("kind")
            sel  = s.get("selector")
            if kind == "field" and sel and sel not in (user_sel, pass_sel) \
                    and s.get("role") != "password" and s.get("value"):
                extras.append({"selector": sel, "value": s["value"]})
            elif kind == "click" and sel and sel != submit_sel:
                blob = f"{sel} {s.get('text','')}"
                if _LOGOUT_RE.search(blob):
                    continue          # never replay a logout click
                extras.append({"click": sel})
        if submit_extra:
            extras.append(submit_extra)
        self._dast_cred_vars["selenium_extra_steps"].set(
            json.dumps(extras) if extras else "")

        # Save the FULL recording too, in order, for literal step-by-step replay
        # (the robust path for overlay/iframe logins). We only drop clicks that
        # look like a logout so replay can never log us out mid-way; everything
        # else — the "open login" click, fields, submit — is kept verbatim.
        literal: list = []
        for s in macro:
            if s.get("kind") == "click":
                blob = f"{s.get('selector','')} {s.get('text','')}"
                if _LOGOUT_RE.search(blob):
                    continue
            literal.append(s)
        self._dast_cred_vars["selenium_macro"].set(
            json.dumps(literal) if literal else "")

        submit_desc = (submit_sel if submit_sel
                       else "Enter / form submit" if submit_extra
                       else "(not detected)")
        self._emit_log(f"[macro] captured {len(macro)} interactions — "
                       f"user={user_sel!r} pass={pass_sel!r} submit={submit_desc!r}")
        pass_note = ("✔ captured (runtime only)" if pass_val
                     else "(type it in Password value before recording Logout)")
        self._show_info_popup("Login Condition",
            f"Captured {len(macro)} interactions.\n\n"
            f"Username selector:  {user_sel   or '(not detected)'}\n"
            f"Password selector:  {pass_sel   or '(not detected)'}\n"
            f"Password value:     {pass_note}\n"
            f"Submit:             {submit_desc}\n\n"
            "Submit is the action that sends the login form — a button click, "
            "or an Enter / form submit when there's no button.\n"
            "The password is held only in this session and is wiped when you "
            "close the program; it's never written to any saved file.")
        self._refresh_dast_creds()
        return True     # signal success to _macro_popup → palomita

    @staticmethod
    def _analyze_login_macro(macro: list) -> tuple:
        """Industry-standard credential-field detection from recorded events.

        Returns (user_selector, user_value, pass_selector, pass_value,
        submit_selector). submit_selector is only set when a real submit *button*
        was clicked; Enter / form submits are handled by the caller.
        """
        # Last password field wins (handles retries / value corrections).
        pass_entry = None
        for s in macro:
            if s.get("kind") == "field" and s.get("selector") and (
                    s.get("role") == "password" or s.get("ftype") == "password"):
                pass_entry = s
        pass_sel = pass_entry.get("selector") if pass_entry else None
        pass_val = pass_entry.get("value") if pass_entry else None

        # Username: prefer an explicit username-role field that occurs before the
        # password; fall back to the last non-password field before it.
        user_sel = user_val = None
        pass_pos = macro.index(pass_entry) if pass_entry in macro else len(macro)
        role_user = [s for s in macro[:pass_pos]
                     if s.get("kind") == "field" and s.get("role") == "username"
                     and s.get("selector")]
        if role_user:
            user_sel = role_user[-1]["selector"]; user_val = role_user[-1].get("value")
        else:
            for s in reversed(macro[:pass_pos]):
                if s.get("kind") == "field" and s.get("selector") \
                        and s.get("role") != "password" and s.get("ftype") != "password":
                    user_sel = s["selector"]; user_val = s.get("value"); break

        # Submit button: a click after the password on a submit-ish element.
        submit_sel = None
        for s in macro[pass_pos + 1:]:
            if s.get("kind") == "click" and s.get("selector"):
                submit_sel = s["selector"]; break
        if not submit_sel:
            sub = next((s for s in macro if s.get("kind") == "submit"
                        and s.get("button")), None)
            if sub: submit_sel = sub["button"]
        return user_sel, user_val, pass_sel, pass_val, submit_sel

    def _dast_record_logout(self):
        """Open browser, replay the recorded login macro to reach the logged-in
        state, then let the user navigate to the logged-out state and capture it.

        The replay is *best-effort and visible*: every step is logged and the
        floating HUD shows live status ("Replaying saved login…", "Logged in ✓ —
        go to the logged-out page…"). If the saved login is incomplete (e.g. the
        password wasn't captured, or a selector no longer matches), the recorder
        no longer dead-ends — it tells the user to finish logging in by hand and
        still proceeds to capture the logout state."""
        # Build replay steps from whatever the login condition captured.
        cfg = self._collect_dast_cfg()
        login_url   = (self._dast_cred_vars["selenium_login_url"].get().strip()
                       or self._dast_url_var.get().strip())
        user_sel    = self._dast_cred_vars["selenium_user_selector"].get().strip()
        user_val    = self._dast_cred_vars["selenium_user_value"].get().strip()
        pass_sel    = self._dast_cred_vars["selenium_pass_selector"].get().strip()
        pass_val    = self._dast_cred_vars["selenium_pass_value"].get().strip()
        submit_sel  = self._dast_cred_vars["selenium_submit_selector"].get().strip()
        extra_raw   = self._dast_cred_vars["selenium_extra_steps"].get().strip()
        macro_raw   = self._dast_cred_vars["selenium_macro"].get().strip()
        succ_sel    = self._dast_cred_vars["login_success_selector"].get().strip()
        succ_txt    = self._dast_cred_vars["login_success_text"].get().strip()

        # Decide up front whether we can drive the login automatically. We can
        # replay only if we have a password to type (or there's literally no
        # password field). Missing password => fall back to manual login instead
        # of erroring out, so the browser still opens and capture still works.
        password_missing = bool(pass_sel and not pass_val)
        can_replay = bool((macro_raw or (user_sel and user_val)
                           or (pass_sel and pass_val) or submit_sel or extra_raw)
                          and not password_missing)

        if password_missing:
            # Non-blocking heads-up. The user can dismiss it and the browser
            # opens right after for a manual login + capture.
            self._show_info_popup("Logout Condition — manual login needed",
                "Your login was recorded, but the password wasn't saved "
                "(passwords are never written to disk).\n\n"
                "The browser will open at the login page. Log in by hand, go to "
                "the logged-OUT page, then press Ctrl+Shift+F12 to capture.\n\n"
                "Tip: type your password into the “Password value” field of the "
                "credentials section first and the login will replay itself "
                "automatically next time.")

        def work(driver, url, done, result, set_status=lambda *_: None):
            import time as _t
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.common.by import By
            from selenium.webdriver.common.keys import Keys

            # Bounded per-element wait so a slightly-off selector can't freeze the
            # whole replay for 15 s per field (that looked like "nothing happens").
            per_wait = max(2, min(int(cfg.selenium_wait_seconds or 15), 8))

            def _find(sel, timeout=None):
                try:
                    return WebDriverWait(driver, timeout or per_wait).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, sel)))
                except Exception:
                    self._emit_log(f"[logout-rec] selector not found: {sel}")
                    return None

            # ── Step 1: navigate to the login page ───────────────────────────
            target = login_url or url
            self._emit_log(f"[logout-rec] navigating to login page: {target}")
            set_status("⏳  Opening login page…")
            try:
                driver.get(target)
            except Exception as e:
                self._emit_log(f"[logout-rec] navigation error: {e!r}")
            _t.sleep(1.0)

            replayed_submit = False

            if not can_replay:
                # Nothing reliable to drive — hand control to the user.
                self._emit_log("[logout-rec] no replayable login (or no saved "
                               "password) — waiting for MANUAL login")
                set_status("👤  Log in by hand, then go to the logged-OUT page "
                           "→ Ctrl+Shift+F12")
            else:
                # ── Step 2: replay the recorded login LITERALLY ──────────────
                # Replay every recorded interaction in the exact order it
                # happened (ZAP/Burp style): the click that opens the login
                # overlay first, then username, then password, then submit. No
                # reordering, no re-clicking the trigger (which would toggle the
                # overlay shut), no inventing reveals. This is the robust path
                # for overlay/iframe logins like XenForo.
                self._emit_log("[logout-rec] replaying saved login (literal)…")
                set_status("🔁  Replaying saved login…")
                macro_raw = self._dast_cred_vars["selenium_macro"].get().strip()
                typed_password = False
                try:
                    macro = json.loads(macro_raw) if macro_raw else []
                except Exception as ex:
                    macro = []
                    self._emit_log(f"[logout-rec] macro JSON invalid: {ex!r}")

                if macro:
                    typed_password = _replay_login_macro(
                        driver, macro, pass_value=(pass_val or None),
                        wait_seconds=cfg.selenium_wait_seconds,
                        log=self._emit_log)
                else:
                    # No literal macro saved (older login condition) — fall back
                    # to the simple field-based drive: user, pass, submit.
                    self._emit_log("[logout-rec] no literal macro — using "
                                   "field-based replay")
                    if user_sel and user_val:
                        el = _find(user_sel)
                        if el:
                            try: el.clear(); el.send_keys(user_val)
                            except Exception: pass
                    if pass_sel and pass_val:
                        el = _find(pass_sel)
                        if el:
                            try:
                                el.clear(); el.send_keys(pass_val)
                                typed_password = True
                            except Exception: pass
                    if submit_sel:
                        el = _find(submit_sel)
                        if el:
                            try: el.click()
                            except Exception: pass
                    elif pass_sel and pass_val:
                        try:
                            from selenium.webdriver.common.keys import Keys as _K
                            driver.find_element(By.CSS_SELECTOR,
                                                pass_sel).send_keys(_K.ENTER)
                        except Exception: pass

                replayed_submit = typed_password
                if not typed_password:
                    self._emit_log("[logout-rec] login could not be driven "
                                   "automatically — finish by hand")
                    set_status("👤  Couldn't auto-fill — log in by hand, then "
                               "go to the logged-OUT page → Ctrl+Shift+F12")

                # Make sure later confirmation logic looks at the top document.
                try: driver.switch_to.default_content()
                except Exception: pass

                # ── Confirm we actually reached the logged-in state ──────────
                set_status("⏳  Waiting for login to complete…")

                def _confirm_logged_in():
                    # Returns True if we can show evidence of a logged-in session.
                    if done.is_set():
                        # User already hit Ctrl+Shift+F12 — don't make them wait
                        # behind an 8 s timeout; go straight to capture.
                        self._emit_log("[logout-rec] capture requested early — "
                                       "skipping login confirmation")
                        return False
                    try:
                        if succ_sel:
                            WebDriverWait(driver, per_wait).until(
                                EC.presence_of_element_located(
                                    (By.CSS_SELECTOR, succ_sel)))
                            self._emit_log("[logout-rec] login confirmed "
                                           "(selector present)")
                            return True
                        if succ_txt:
                            WebDriverWait(driver, per_wait).until(
                                lambda d: succ_txt in d.page_source)
                            self._emit_log("[logout-rec] login confirmed "
                                           "(text present)")
                            return True
                        # No success marker configured: give the navigation a
                        # moment, then assume success if no VISIBLE password
                        # field remains (hidden twins in the DOM don't count —
                        # XenForo et al. always keep one around).
                        _t.sleep(2)
                        gone = not driver.execute_script(
                            "var ps=document.querySelectorAll('input[type=password]');"
                            "for(var i=0;i<ps.length;i++)"
                            " if(ps[i].offsetParent!==null) return true;"
                            "return false;")
                        self._emit_log("[logout-rec] login replayed "
                                       f"(heuristic logged_in={gone})")
                        return gone
                    except Exception:
                        self._emit_log("[logout-rec] login confirmation timed "
                                       "out — continuing anyway")
                        return False

                logged_in = _confirm_logged_in()
                if logged_in:
                    set_status("✅  Logged in — go to the logged-OUT page, "
                               "then Ctrl+Shift+F12")
                else:
                    set_status("⚠️  Couldn't confirm login — finish by hand, "
                               "then Ctrl+Shift+F12 on the logged-OUT page")

            self._emit_log("[logout-rec] ready — navigate to the logged-OUT "
                           "state and press Ctrl+Shift+F12 to capture")

            # ── Step 3: wait for the user to reach the logout state ──────────
            while not done.is_set():
                if done.wait(0.4):
                    break

            # ── Step 4: capture the logged-out page ──────────────────────────
            set_status("📸  Capturing logout state…")
            snap = {}
            try:
                raw = driver.execute_script(_LOGOUT_CAPTURE_JS)
                if raw:
                    snap = json.loads(raw)
                else:
                    self._emit_log("[logout-rec] capture returned no data")
            except Exception as e:
                self._emit_log(f"[logout-rec] JS capture error: {e!r}")
            result["snapshot"] = snap if isinstance(snap, dict) else {}
            try:
                result["final_url"] = driver.current_url
            except Exception:
                result["final_url"] = snap.get("url", "") if isinstance(snap, dict) else ""
            try:
                result["cookies"] = driver.get_cookies() or []
            except Exception:
                result["cookies"] = []
            self._emit_log(f"[logout-rec] captured url={result.get('final_url','')!r} "
                           f"signals={len(result.get('snapshot',{}).get('hints',[]))}")

        result = self._record_in_browser(
            "Record Logout Condition", "⏺ Logout Condition",
            [], work, w_pct=0.34, h_pct=0.32)
        if result is None: return False     # cancelled or browser error — no palomita

        final_url  = result.get("final_url","").strip()
        snapshot   = result.get("snapshot", {})
        hints      = snapshot.get("hints", [])
        page_title = snapshot.get("title","")
        proposed_re = ""
        if final_url:
            path_part = urlparse(final_url).path.rstrip("/") or "/"
            proposed_re = _re.escape(path_part) + r"(\?|$)"

        confirm = self._create_popup("Logout condition — review & confirm",
                                     w_pct=0.50, h_pct=0.66)
        self._popup_hdr(confirm, "Logout Condition",
                        subtitle="review captured signals", icon="🔓")

        # Footer FIRST, pinned to the bottom, so however much content the body
        # holds the Apply/Cancel buttons can never be pushed off-screen (that's
        # exactly what used to happen — and with Apply unreachable, the logout
        # condition never registered and no ✔ appeared).
        _cb: dict = {"apply": lambda: None}
        foot_bg = T["panel_bg"]
        foot = tk.Frame(confirm, bg=foot_bg, padx=28, pady=12)
        foot.pack(side="bottom", fill="x")
        self._btn(foot, "Apply", lambda: _cb["apply"](), "accent")\
            .pack(side="right", padx=(6, 0))
        self._btn(foot, "Cancel", lambda: confirm.close(), "flat")\
            .pack(side="right", padx=(6, 0))
        tk.Frame(confirm, bg=T["border"], height=1)\
            .pack(side="bottom", fill="x")

        # Body inside a scrollable canvas — long signal lists just scroll.
        canvas = tk.Canvas(confirm, bg=T["bg"], highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(confirm, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        cbody = tk.Frame(canvas, bg=T["bg"], padx=28, pady=14)
        cwin = canvas.create_window((0, 0), window=cbody, anchor="nw")

        def _sync_scroll(_e=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
        def _sync_width(e):
            canvas.itemconfigure(cwin, width=e.width)
        cbody.bind("<Configure>", _sync_scroll)
        canvas.bind("<Configure>", _sync_width)

        def _wheel(e):
            try:
                canvas.yview_scroll(-1 * int(e.delta / 120), "units")
            except Exception:
                pass
        # Bound to the widgets (not bind_all) so the bindings die with them.
        canvas.bind("<MouseWheel>", _wheel)
        cbody.bind("<MouseWheel>", _wheel)

        cbody.columnconfigure(1, weight=1)
        row_idx = [0]

        def _row(widget_or_text, *, col=0, span=1, sticky="w", advance=True, **gkw):
            w = widget_or_text
            if isinstance(w, str):
                w = self._lbl(cbody, w, size=9, fg=T["muted"], wraplength=430, anchor="w")
                span = 2
            w.grid(row=row_idx[0], column=col, columnspan=span,
                   sticky=sticky, **gkw)
            if advance: row_idx[0] += 1
            return w

        def _field(label, value_var):
            _row(self._lbl(cbody, label, size=10, fg=T["muted"], anchor="e"),
                 sticky="e", advance=False, padx=(0, 8), pady=3)
            e = ttk.Entry(cbody, textvariable=value_var)
            _row(e, col=1, sticky="ew", pady=3)
            return e

        _row(self._lbl(cbody, "Captured URL", size=10, fg=T["muted"], anchor="e"),
             sticky="e", advance=False, padx=(0, 8), pady=3)
        _row(self._lbl(cbody, final_url or "(none)", size=10,
                       fg=T["text"], anchor="w", wraplength=420), col=1)
        re_var = tk.StringVar(value=proposed_re)
        _row(self._lbl(cbody, "Logout URL regex", size=10, fg=T["muted"], anchor="e"),
             sticky="e", advance=False, padx=(0, 8), pady=3)
        _row(ttk.Entry(cbody, textvariable=re_var), col=1, sticky="ew", pady=3)
        _row("URLs matching this regex are SKIPPED so the scanner never logs itself out.")
        _row(tk.Frame(cbody, bg=T["border"], height=1), span=2, sticky="ew", pady=10)
        _row(self._lbl(cbody, "SESSION DETECTION", size=9,
                       fg=T["muted"], bold=True, anchor="w"), span=2)
        _row("Optionally tell the scanner what a LOGGED-IN page looks like "
             "so it can detect session loss mid-scan and re-authenticate.")
        sel_var = tk.StringVar(
            value=self._dast_cred_vars["login_success_selector"].get())
        _field("Logged-in selector", sel_var)
        _row("CSS selector present ONLY when logged in (e.g. #user-avatar).")
        txt_var = tk.StringVar(
            value=self._dast_cred_vars["login_success_text"].get())
        _field("Logged-in text", txt_var)
        _row("Text ONLY visible when logged in (e.g. 'My Account').")

        if hints or page_title or snapshot.get("has_password_field") \
                or snapshot.get("has_login_form"):
            _row(tk.Frame(cbody, bg=T["border"], height=1),
                 span=2, sticky="ew", pady=(10, 4))
            _row("Signals detected on logout page (for reference):")
            strong = []
            if snapshot.get("has_password_field"):
                strong.append("password field present (typical of a login page)")
            if snapshot.get("has_login_form"):
                strong.append("login form present")
            for s in strong:
                _row(f"  ✓ {s}")
            # Collapse whitespace defensively — old captures could contain a
            # whole <form> innerText with embedded newlines (the giant blank
            # block in the popup). New captures are already clean.
            clean_hints = []
            for h in hints:
                h = _re.sub(r"\s+", " ", str(h)).strip()[:80]
                if h and h not in clean_hints:
                    clean_hints.append(h)
            for h in ([f"Page title: {page_title}"] if page_title else []) \
                    + clean_hints[:8]:
                _row(f"  · {h}")
        elif not final_url:
            # Nothing came back at all — make the dead-end obvious instead of a
            # blank popup, and tell the user what to do.
            _row(tk.Frame(cbody, bg=T["border"], height=1),
                 span=2, sticky="ew", pady=(10, 4))
            _row("⚠️  No page data was captured. Make sure you pressed "
                 "Ctrl+Shift+F12 *while on the logged-out page* (the browser "
                 "must still be open). You can type the Logout URL regex above "
                 "by hand and Apply.")

        applied: list[bool] = [False]
        def _apply():
            re_val  = re_var.get().strip()
            sel_val = sel_var.get().strip()
            txt_val = txt_var.get().strip()
            if re_val:  self._dast_cred_vars["logout_url_re"].set(re_val)
            if sel_val: self._dast_cred_vars["login_success_selector"].set(sel_val)
            if txt_val: self._dast_cred_vars["login_success_text"].set(txt_val)
            applied[0] = True
            self._emit_log(f"[logout-rec] applied — regex={re_val!r} "
                           f"selector={sel_val!r} text={txt_val!r}")
            self._refresh_dast_creds(); confirm.close()

        _cb["apply"] = _apply           # footer Apply button → this handler

        # Mouse-wheel must also work when the pointer is over the labels and
        # entries inside the body, not just the canvas itself.
        def _bind_wheel_rec(w):
            try: w.bind("<MouseWheel>", _wheel)
            except Exception: pass
            for child in w.winfo_children():
                _bind_wheel_rec(child)
        _bind_wheel_rec(cbody)

        self.wait_window(confirm._win)
        if not applied[0]:
            self._emit_log("[logout-rec] cancelled — no changes applied")
            return False
        return True     # signal success to _macro_popup → palomita

    # ── Scan pipeline ─────────────────────────────────────────────────────────
    def _start_scan(self):
        self._run_async(self._do_scan, label="full pipeline scan")

    def _request_cancel(self):
        if self._busy:
            self._cancel_evt.set()
            self._emit_log(f"[scan] {_t('cancel_requested')}")
            self._set_status(_t("cancelling"))
        else:
            self._emit_log(f"[scan] {_t('nothing_to_cancel')}")

    def _do_scan(self):
        selected = {k for k, v in self._scan_vars.items() if v.get()}
        if not selected:
            self._emit_log("[scan] nothing selected"); return
        self._cancel_evt.clear()
        target       = Path(self._target_var.get()).resolve()
        reports_root = Path(self._reports_var.get()).resolve()
        reports_root.mkdir(parents=True, exist_ok=True)

        if bool({"sca","code"} & selected) and (
                not target.exists() or not target.is_dir()):
            self._emit_log(f"[scan] target folder missing: {target}"); return

        mode    = "+".join(sorted(selected))
        out_dir = reports_root / f"report_{_ts()}_{mode}"
        out_dir.mkdir(parents=True, exist_ok=True)
        self._emit_log(f"[scan] pipeline: {mode.upper()}")
        self._emit_log(f"[scan] output → {out_dir}")

        try:    v = _run(["snyk","--version"]).stdout.strip()
        except Exception: v = "?"

        results: dict[str, Any] = {"sca":None,"code":None,"dast":None,"api":None,"secrets":None}
        for k in ("sca","code","dast","api","secrets"):
            self._event_queue.put(
                ("stage", (k, "running" if k in selected else "skipped")))

        jobs: list[tuple[str, Callable[[], None]]] = []
        def _stage(key, fn, *a, **kw):
            jobs.append((key, lambda: results.__setitem__(key, fn(*a, **kw)[0])))

        if "sca"  in selected: _stage("sca",  run_snyk_test, target, out_dir, self._emit_log)
        if "code" in selected: _stage("code", run_snyk_code, target, out_dir, self._emit_log)
        if "dast" in selected:
            dast_cfg = self._collect_dast_cfg()
            if not dast_cfg.url or dast_cfg.url == "https://":
                self._emit_log("[dast] no URL configured — skipping DAST")
                self._event_queue.put(("stage",("dast","skipped")))
            else:
                _stage("dast", run_dast, dast_cfg, out_dir, self._emit_log,
                       cancel=self._cancel_evt)
        if "api" in selected:
            api_cfg = self._collect_api_cfg()
            if not api_cfg.spec_source:
                self._emit_log("[api] no spec configured — skipping API scan")
                self._event_queue.put(("stage",("api","skipped")))
            else:
                _stage("api", run_api, api_cfg, out_dir, self._emit_log,
                       cancel=self._cancel_evt)
        if "secrets" in selected:
            def _run_secrets_stage():
                try:
                    self._emit_log("[secrets] running secret scan as pipeline stage…")
                    result = scan_path(target, self._emit_log,
                                       cancel=self._cancel_evt,
                                       git_secrets_status=_GIT_SECRETS_STATUS)
                    sec_dir = out_dir / "secrets"
                    write_secrets_report(result, sec_dir)
                    self._emit_log(
                        f"[secrets] {result['total']} finding(s) across "
                        f"{result['scanned_files']} file(s)")
                    results["secrets"] = result
                except Exception as e:
                    self._emit_log(f"[secrets] stage failed: {e!r}")
                    results["secrets"] = None
            jobs.append(("secrets", _run_secrets_stage))

        def run_stage(item):
            key, fn = item
            try:
                fn()
                self._event_queue.put(("stage",(key,"done")))
            except Exception as e:
                self._event_queue.put(("stage",(key,"failed")))
                self._emit_log(f"[scan] {key} failed: {e!r}")

        if len(jobs) > 1:
            self._emit_log(f"[scan] running {len(jobs)} stages concurrently")
            with ThreadPoolExecutor(max_workers=len(jobs)) as ex_:
                list(ex_.map(run_stage, jobs))
        else:
            for j in jobs: run_stage(j)

        # ── Persist each completed stage result to the cumulative state store ──
        # This ensures the next report always includes the last run of EVERY type,
        # regardless of which types were selected in this session.
        dast_url_hint  = ""
        api_spec_hint  = ""
        try: dast_url_hint  = self._dast_url_var.get().strip()
        except Exception: pass
        try: api_spec_hint  = self._api_spec_var.get().strip()
        except Exception: pass

        _kind_targets = {
            "sca":     str(target),
            "code":    str(target),
            "dast":    dast_url_hint  or str(target),
            "api":     api_spec_hint  or str(target),
            "secrets": str(target),
        }
        state = getattr(self, "_scan_state", None)
        if state:
            for kind in ("sca", "code", "dast", "api", "secrets"):
                raw = results.get(kind)
                if raw is not None:
                    try:
                        state.save_kind(
                            kind, raw,
                            target=_kind_targets.get(kind, str(target)),
                            snyk_version=v, mode=mode)
                        self._emit_log(f"[state] {kind} result persisted to cumulative store")
                    except Exception as e:
                        self._emit_log(f"[state] could not save {kind}: {e!r}")
        else:
            self._emit_log("[state] ScanStateStore not available — skipping persistence")

        # ── Build cumulative context (merges current results + last-of-each-kind) ─
        if state:
            ctx = build_cumulative_context(
                state,
                target_hint=target,
                snyk_version_hint=v,
                current_results=results,
            )
            self._emit_log("[report] building cumulative report (all scan types merged)")
        else:
            # Fallback: current-session-only (original behaviour)
            ctx = build_context(results["sca"], results["code"], target, v,
                                dast_data=results["dast"], api_data=results["api"],
                                secrets_data=results["secrets"])

        ctx["scan_mode"] = mode
        self._emit_log(
            f"[scan] cumulative total: {ctx['total']}  "
            f"crit={ctx['counts']['critical']}  high={ctx['counts']['high']}  "
            f"med={ctx['counts']['medium']}  low={ctx['counts']['low']}  "
            f"secrets={ctx.get('secrets_total',0)}")
        report   = render_html(ctx, out_dir)
        csv_path = export_csv(ctx, out_dir / "findings.csv")
        self._emit_log(f"[report] CSV bundle (ZIP): {csv_path}  (sca/sast/dast/api/secrets sheets + summary)")
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
            "generated_at": ctx["generated_at"], "target": ctx["target"],
            "mode": mode, "counts": ctx["counts"], "total": ctx["total"],
            "sca_total": ctx["sca_total"], "code_total": ctx["code_total"],
            "dast_total": ctx.get("dast_total",0), "api_total": ctx.get("api_total",0),
            "snyk_version": ctx["snyk_version"],
            "secrets_total": ctx.get("secrets_total", 0),
        }
        (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        try:
            rec = update_history_after_scan(
                reports_root, ctx, meta,
                actor=getattr(self, "_user", ""), report_dir=out_dir)
            self._emit_log(
                f"[history] recorded scan — remediated {rec.get('remediated_count',0)}, "
                f"new {rec.get('introduced_count',0)} since last {mode.upper()} run")
        except Exception as e:
            self._emit_log(f"[history] could not update remediation history: {e!r}")

        # ── Push to App Inventory ──────────────────────────────────────────────
        active_app = getattr(self, "_active_app", None)
        if active_app and active_app.get("id"):
            try:
                self._inv_store.record_scan(active_app["id"], meta)
                self._emit_log(
                    f"[inventory] scan recorded for app '{active_app['name']}'")
                self._event_queue.put(("inv_refresh", active_app["id"]))
            except Exception as e:
                self._emit_log(f"[inventory] could not update app record: {e!r}")

        c = ctx["counts"]
        secrets_crit = sum(1 for s in ctx.get("secrets", {}).get("findings", [])
                           if s.get("severity") in ("critical", "high"))
        gate = "FAIL" if (c.get("critical",0) or c.get("high",0) or secrets_crit) else "PASS"
        self._emit_log(
            f"[gate] {gate}  (critical={c.get('critical',0)} high={c.get('high',0)} "
            f"medium={c.get('medium',0)} low={c.get('low',0)} "
            f"secrets_crit_high={secrets_crit})")
        self._last_context    = ctx
        self._last_report_dir = out_dir
        self._emit_log(f"[report] HTML: {report}")
        self._emit_log(f"[report] CSV:  {csv_path}")
        self._event_queue.put(("report", str(report)))

    def _open_last(self):
        if self._last_report and self._last_report.exists():
            webbrowser.open(self._last_report.as_uri())

    def _export_last_csv(self):
        if not self._last_context:
            self._show_info_popup("Export CSV", "Run a scan first."); return
        path = filedialog.asksaveasfilename(
            title="Export CSV bundle (ZIP)",
            defaultextension=".zip",
            initialfile="findings.zip",
            filetypes=[("ZIP bundle", "*.zip"), ("CSV", "*.csv"), ("All", "*.*")])
        if not path: return
        out = export_csv(self._last_context, Path(path).with_suffix(".csv"))
        self._log_line(f"[csv] ZIP bundle → {out}  (sheets: summary / sca / sast / dast / api / secrets)")

    # ── Threading / event loop ────────────────────────────────────────────────
    def _run_async(self, fn: Callable[[], None], label: str = ""):
        if self._busy:
            self._log_line(f"[busy] ignoring '{label}' — another op in progress"); return
        self._busy = True
        self._update_stop_btn_style()
        self._set_status(f"Running: {label}…")
        def wrap():
            try: fn()
            except Exception as e: self._log_line(f"[error] {e!r}")
            finally: self._event_queue.put(("__done__", label))
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
                        pill.config(text=label, bg=bg, fg=fg)
                elif kind == "report":
                    self._last_report = Path(payload)
                    self._open_btn.config(state="normal")
                    self._csv_btn.config(state="normal")
                    self._refresh_recent()
                    self._refresh_rep_tree()
                    if self._auto_open:
                        webbrowser.open(self._last_report.as_uri())
                elif kind == "api_preview":
                    fmt, ops, count = payload
                    for iid in self._ep_tree.get_children():
                        self._ep_tree.delete(iid)
                    for op in ops:
                        ctype   = op.get("ctype") or "—"
                        secured = "✓" if op.get("secured") else "—"
                        self._ep_tree.insert("","end",
                            values=(op["method"], op["url"], secured, ctype))
                    self._ep_count_lbl.config(
                        text=f"Format: {fmt}  ·  {count} endpoint(s) detected")
                    self._emit_log(f"[api-preview] {fmt} — {count} endpoints")
                elif kind == "secrets":
                    result, html = payload
                    self._secrets_busy = False
                    if hasattr(self, "_secrets_run_btn"):
                        self._secrets_run_btn.config(state="normal")
                    if result is None:
                        if hasattr(self, "_secrets_count_lbl"):
                            self._secrets_count_lbl.config(text="Scan failed — see console.")
                    else:
                        self._last_secrets_html = Path(html) if html else None
                        if hasattr(self, "_secrets_tree"):
                            for iid in self._secrets_tree.get_children():
                                self._secrets_tree.delete(iid)
                            for f in result.get("findings", []):
                                self._secrets_tree.insert(
                                    "", "end",
                                    values=(f["severity"], f.get("secret_type", f["rule"]),
                                            f["file"], f.get("line", "?"),
                                            f.get("match", "")))
                        c = result.get("counts", {})
                        if hasattr(self, "_secrets_count_lbl"):
                            self._secrets_count_lbl.config(
                                text=f"{result.get('total',0)} secret(s) · "
                                     f"crit {c.get('critical',0)} · high {c.get('high',0)} · "
                                     f"med {c.get('medium',0)} · low {c.get('low',0)}")
                        if hasattr(self, "_secrets_open_btn"):
                            self._secrets_open_btn.config(
                                state="normal" if self._last_secrets_html else "disabled")
                elif kind == "__done__":
                    self._busy = False
                    self._update_stop_btn_style()
                    self._set_status(_t("ready"))
                    self._refresh_scan_btn()
                elif kind == "inv_refresh":
                    # Update inventory tab after a scan records results
                    inv_tab = getattr(self, "_inv_tab", None)
                    if inv_tab:
                        try:
                            inv_tab.refresh()
                        except Exception:
                            pass
        except queue.Empty: pass
        if self._auth_proc is not None:
            self._tick_auth_poll()
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
            self._console_btn.configure(text=f"▥  Console ({self._unread_log})")

    def _update_stop_btn_style(self):
        """Update stop button appearance based on scan state."""
        btn = getattr(self, "_stop_icon_btn", None)
        if not btn: return
        if self._busy:
            btn.configure(fg=T["err"], highlightbackground=T["err"],
                          highlightcolor=T["err"],
                          activeforeground=T["err"])
        else:
            btn.configure(fg=T["muted"], highlightbackground=T["muted"],
                          highlightcolor=T["muted"],
                          activeforeground=T["muted"])

    def _set_status(self, s: str): self._status_var.set(s)
    def _emit_log(self, s: str):   self._event_queue.put(("log", s))

# ── Loading splash ────────────────────────────────────────────────────────────
def _splash_read_dark_pref() -> bool:
    """Read dark_mode from .scanner_settings.json without importing the app.
    Returns False (light) if the file is absent or unreadable — matching the
    default T = _PALETTE_LIGHT initialisation above."""
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        return bool(data.get("dark_mode", False))
    except Exception:
        return False


class BootSplash(tk.Tk):
    """Borderless startup splash whose look & feel mirrors ScannerApp exactly:
    ribbon header with amber stripe + red brand underline, themed body and log
    console.  Reads the saved dark_mode preference so the splash always matches
    whatever theme the user last selected (first launch = light)."""

    def __init__(self):
        super().__init__()
        self.overrideredirect(True)
        try: self.attributes("-topmost", True)
        except Exception: pass

        # Apply palette into the global T dict *before* building any widgets,
        # exactly as ScannerApp._load_settings() + _apply_palette() would do.
        _apply_palette(_splash_read_dark_pref())

        w, h = 600, 400
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")

        # Outermost: 2-px amber border (mirrors popup / ReportsViewer style)
        self.configure(bg=T["accent"])
        outer = tk.Frame(self, bg=T["accent"], padx=2, pady=2)
        outer.pack(fill="both", expand=True)

        # Main container — uses T["bg"] so it adapts to light/dark
        c = tk.Frame(outer, bg=T["bg"])
        c.pack(fill="both", expand=True)

        # ── Ribbon header (mirrors ScannerApp._build_ribbon exactly) ──────
        ribbon = tk.Frame(c, bg=T["panel_bg"])
        ribbon.pack(fill="x")

        # Top amber accent stripe (2 px)
        tk.Frame(ribbon, bg=T["accent"], height=2).pack(fill="x", side="top")

        inner_row = tk.Frame(ribbon, bg=T["panel_bg"])
        inner_row.pack(fill="x", side="top")

        # Brand block
        brand = tk.Frame(inner_row, bg=T["panel_bg"], padx=10, pady=0)
        brand.pack(side="left")
        # Red accent bar under brand (accent2)
        tk.Frame(brand, bg=T["accent2"], height=2).pack(fill="x", side="top")
        brand_inner = tk.Frame(brand, bg=T["panel_bg"], pady=4)
        brand_inner.pack(fill="x")
        tk.Label(brand_inner, text="🛡", font=(_FUI, 18),
                 bg=T["panel_bg"], fg=T["accent"]).pack(side="left", padx=(0, 6))
        tk.Label(brand_inner, text="VULNERABILITY SCANNER",
                 font=(_FUI, 11, "bold"),
                 bg=T["panel_bg"], fg=T["accent"]).pack(side="left")

        # OS / user tag aligned right
        os_tag = "macOS" if IS_MAC else ("Windows" if IS_WIN else "Linux")
        right_lbl = tk.Frame(inner_row, bg=T["panel_bg"])
        right_lbl.pack(side="right", padx=12)
        tk.Label(right_lbl, text=f"{os_tag}  ·  {_detect_user()}",
                 font=(_FUI, 9), bg=T["panel_bg"], fg=T["muted"]).pack(pady=6)

        # Bottom border line of ribbon
        tk.Frame(ribbon, bg=T["border"], height=1).pack(fill="x", side="bottom")

        # ── Body ──────────────────────────────────────────────────────────
        body = tk.Frame(c, bg=T["bg"])
        body.pack(fill="both", expand=True, padx=22, pady=(10, 14))

        # ── Rotating Globe animation ───────────────────────────────────────
        import math as _math
        GR = 48                         # globe radius (px)
        GW, GH = GR * 2 + 8, GR * 2 + 8
        self._globe_cv = tk.Canvas(body, width=GW, height=GH,
                                   bg=T["bg"], bd=0, highlightthickness=0)
        self._globe_cv.pack(side="left", padx=(0, 14))
        self._globe_angle = 0.0

        def _draw_globe(angle):
            cv = self._globe_cv
            cv.delete("globe")
            cx, cy = GW // 2, GH // 2
            # Sphere outline
            cv.create_oval(cx - GR, cy - GR, cx + GR, cy + GR,
                           outline=T["accent"], width=2, tags="globe")
            # Latitude lines (fixed)
            for lat_frac in (-0.55, -0.25, 0, 0.25, 0.55):
                ry = int(GR * _math.sqrt(max(0, 1 - lat_frac**2)))
                yy = cy + int(GR * lat_frac)
                if ry > 2:
                    cv.create_oval(cx - ry, yy - 4, cx + ry, yy + 4,
                                   outline=T["muted"], width=1, tags="globe")
            # Longitude arcs (rotate with angle) — 4 meridians
            N = 40
            for lon_offset in (0, 0.5, 1.0, 1.5):
                pts = []
                for i in range(N + 1):
                    lat = _math.pi * (i / N - 0.5)
                    lon = angle + _math.pi * lon_offset
                    x3 = _math.cos(lat) * _math.cos(lon)
                    y3 = _math.sin(lat)
                    if _math.cos(lat) * _math.sin(lon) < 0:  # back-face cull
                        continue
                    px = int(cx + GR * x3)
                    py = int(cy - GR * y3)
                    pts.append((px, py))
                for j in range(len(pts) - 1):
                    cv.create_line(pts[j], pts[j + 1],
                                   fill=T["muted"], width=1, tags="globe")
            # Highlight dot (top-left quadrant)
            hx = cx - int(GR * 0.35)
            hy = cy - int(GR * 0.38)
            cv.create_oval(hx - 5, hy - 5, hx + 5, hy + 5,
                           fill=T["accent"], outline="", tags="globe")

        def _spin_globe():
            if self._done or self._error is not None:
                return
            self._globe_angle = (self._globe_angle + 0.06) % (2 * _math.pi)
            _draw_globe(self._globe_angle)
            self.after(40, _spin_globe)   # ~25 fps

        _draw_globe(0.0)
        self.after(40, _spin_globe)

        # Right side: step label + progress + log stacked vertically
        right_col = tk.Frame(body, bg=T["bg"])
        right_col.pack(side="left", fill="both", expand=True)

        # Current-step label — amber bold, same as section headers in app
        self._step_var = tk.StringVar(value="Preparing…")
        tk.Label(right_col, textvariable=self._step_var,
                 font=(_FUI, 11, "bold"),
                 bg=T["bg"], fg=T["accent"], anchor="w").pack(fill="x")

        # Progress bar styled with the current palette
        pb_style = ttk.Style(self)
        try: pb_style.theme_use("clam")
        except tk.TclError: pass
        pb_style.configure("Splash.Horizontal.TProgressbar",
                           troughcolor=T["surface2"],
                           background=T["accent"],
                           bordercolor=T["border"],
                           lightcolor=T["accent"],
                           darkcolor=T["accent"])
        self._pb = ttk.Progressbar(right_col, style="Splash.Horizontal.TProgressbar",
                                   mode="determinate", maximum=100)
        self._pb.pack(fill="x", pady=(6, 10))

        # Log console card — same panel_bg + border as body cards in app
        logwrap = tk.Frame(right_col, bg=T["panel_bg"],
                           highlightthickness=1,
                           highlightbackground=T["border"])
        logwrap.pack(fill="both", expand=True)

        # Thin accent stripe at top of log card (visual rhythm)
        tk.Frame(logwrap, bg=T["accent"], height=1).pack(fill="x", side="top")

        self._log = tk.Text(logwrap, bg=T["panel_bg"], fg=T["muted"],
                            relief="flat", font=(_FMONO, 9),
                            padx=10, pady=8, height=8,
                            state="disabled", wrap="none",
                            insertbackground=T["text"],
                            selectbackground=T["accent"],
                            selectforeground=T["button_fg"])
        sb = tk.Scrollbar(logwrap, command=self._log.yview,
                          bg=T["panel_bg"], troughcolor=T["surface2"],
                          relief="flat", bd=0)
        self._log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._log.pack(fill="both", expand=True)

        # ── State ─────────────────────────────────────────────────────────
        self._q: queue.Queue = queue.Queue()
        self._done = False
        self._error: Optional[str] = None
        self.after(60, self._pump)

    # progress callback used by _load_runtime (runs in worker thread)
    def progress(self, kind, payload):
        self._q.put((kind, payload))

    def _append(self, text: str):
        self._log.configure(state="normal")
        self._log.insert("end", text.rstrip() + "\n")
        # keep the last ~200 lines
        lines = int(self._log.index("end-1c").split(".")[0])
        if lines > 200:
            self._log.delete("1.0", f"{lines - 200}.0")
        self._log.see("end")
        self._log.configure(state="disabled")

    def _pump(self):
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "step":
                    i, total, label = payload
                    self._step_var.set(f"[{i}/{total}]  {label}")
                    self._pb.configure(value=int(i / max(total, 1) * 100))
                elif kind == "log":
                    self._append(str(payload))
                elif kind == "error":
                    self._error = str(payload)
                elif kind == "done":
                    self._step_var.set("✔  Ready — launching…")
                    self._pb.configure(value=100)
                    self._done = True
        except queue.Empty:
            pass
        if self._done or self._error is not None:
            self.after(280, self.quit)   # leave the splash mainloop
            return
        self.after(60, self._pump)


def run_boot() -> Optional[str]:
    """Show the splash, run _load_runtime in a worker thread, block until done.
    Returns None on success or an error string."""
    splash = BootSplash()
    holder: dict = {"error": None}

    def worker():
        try:
            _load_runtime(progress=splash.progress)
        except Exception as e:
            import traceback
            holder["error"] = f"{e!r}\n\n{traceback.format_exc()}"
            splash.progress("log", f"ERROR: {e!r}")
            splash.progress("error", str(e))
        else:
            splash.progress("done", None)

    threading.Thread(target=worker, daemon=True).start()
    splash.mainloop()
    try: splash.destroy()
    except Exception: pass
    return holder["error"]


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    # 1) Real loading splash while heavy deps + git-secrets are fetched.
    err = run_boot()
    if err:
        msg = ("Scanner could not load its dependencies:\n\n" + err +
               "\n\nUsually a missing package or corporate TLS proxy.")
        try:
            root = tk.Tk(); root.withdraw()
            messagebox.showerror("Vulnerability Scanner — startup failed", msg)
        except Exception:
            print(msg, file=sys.stderr)
        return

    # 2) Launch the main application.
    try:
        app = ScannerApp()
    except Exception as e:
        import traceback
        msg = (f"Scanner could not start:\n\n{e!r}\n\n"
               "Usually a missing package or corporate TLS proxy.\n\n"
               + traceback.format_exc())
        try:
            root = tk.Tk(); root.withdraw()
            messagebox.showerror("Vulnerability Scanner — startup failed", msg)
        except Exception:
            print(msg, file=sys.stderr)
        raise
    app.mainloop()

if __name__ == "__main__":
    main()