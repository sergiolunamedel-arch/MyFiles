"""snyk_sca_sast.py — SCA (snyk test) + SAST (snyk code) scan engines.

Exposes:
    run_snyk_test(target, out_dir, log)  → (data, path)
    run_snyk_code(target, out_dir, log)  → (data, path)
    export_sarif(out_dir)                → Path | None
    export_merged_json(out_dir)          → Path | None
    CheckResult, check_python, check_node, check_npm, check_snyk, check_auth
    install_node, install_snyk, start_snyk_auth
"""

from __future__ import annotations

import json, os, sys, shutil, subprocess, platform
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional


# ── Platform flags ────────────────────────────────────────────────────────────
IS_WIN   = os.name == "nt"
IS_MAC   = sys.platform == "darwin"
IS_LINUX = not IS_WIN and not IS_MAC


def _augment_path() -> None:
    """When launched from Finder/Dock (.app) or a desktop launcher, the process
    PATH is often minimal and misses Homebrew / user bin dirs, so tools like
    node, npm, snyk and brew become invisible. Prepend the usual locations
    (only those that exist) so _which() can find them on macOS / Linux."""
    if IS_WIN:
        return
    home = Path.home()
    candidates = [
        "/opt/homebrew/bin", "/opt/homebrew/sbin",   # Apple-silicon Homebrew
        "/usr/local/bin", "/usr/local/sbin",          # Intel Homebrew / common
        str(home / ".local" / "bin"), str(home / "bin"),
        "/opt/local/bin",                             # MacPorts
        str(home / ".nvm" / "current" / "bin"),       # nvm symlink (if present)
    ]
    cur = os.environ.get("PATH", "")
    parts = cur.split(os.pathsep)
    extra = [c for c in candidates if c and c not in parts and os.path.isdir(c)]
    if extra:
        os.environ["PATH"] = os.pathsep.join(extra + parts)


_augment_path()



# ── Re-export bootstrap helpers so callers don't need to import the main file ─
def _pip(args: list[str]) -> None:
    cmd = [sys.executable, "-m", "pip", "install", "--user",
           "--disable-pip-version-check"] + args
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        env = os.environ.copy()
        env["PIP_TRUSTED_HOST"] = "pypi.org files.pythonhosted.org pypi.python.org"
        hosts = ["--trusted-host", "pypi.org",
                 "--trusted-host", "files.pythonhosted.org",
                 "--trusted-host", "pypi.python.org"]
        subprocess.check_call(cmd + hosts, env=env,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    import site
    us = site.getusersitepackages()
    if us not in sys.path:
        sys.path.insert(0, us)


# ── Platform utils (minimal subset needed here) ───────────────────────────────
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


def _run_tls(args, cwd=None, timeout=900,
             log: Callable[[str], None] = lambda _: None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    log(f"$ {' '.join(args)}")
    r = _run(args, cwd=cwd, env=env, timeout=timeout)
    combined = ((r.stdout or "") + (r.stderr or "")).lower()
    if r.returncode != 0 and any(
            m in combined for m in ("self signed certificate", "unable to verify",
                                    "ssl", "cert_", "econnreset")):
        log("[tls-retry] retrying with NODE_TLS_REJECT_UNAUTHORIZED=0")
        env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
        r = _run(args, cwd=cwd, env=env, timeout=timeout)
    return r


# ── Package-manager / tool resolvers ──────────────────────────────────────────
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
        return ["sudo", "-n"]   # -n: never prompt; fail fast if a password is required
    return []


def _download_file(url: str, dest: Path, log: Callable[[str], None],
                   timeout: int = 120) -> bool:
    import urllib.request
    try:
        log(f"[download] {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "vuln-scanner/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - fixed host
            data = resp.read()
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
    # Linux: detect musl (Alpine) vs glibc.
    if Path("/etc/alpine-release").exists():
        return "snyk-alpine-arm64" if is_arm else "snyk-alpine"
    return "snyk-linux-arm64" if is_arm else "snyk-linux"


def _install_standalone_snyk(log: Callable[[str], None]) -> bool:
    """Universal npm-free fallback: download the official Snyk CLI binary to
    ~/.local/bin (or %LOCALAPPDATA% on Windows) and make it executable."""
    asset = _standalone_snyk_asset()
    if not asset:
        return False
    if IS_WIN:
        bindir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "snyk" / "bin"
        target = bindir / "snyk.exe"
    else:
        bindir = Path.home() / ".local" / "bin"
        target = bindir / "snyk"
    url = f"https://static.snyk.io/cli/latest/{asset}"
    log(f"[snyk] installing standalone CLI ({asset})…")
    if not _download_file(url, target, log, timeout=180):
        return False
    if not IS_WIN:
        try: os.chmod(target, 0o755)
        except Exception: pass
    # Make sure the freshly-installed binary is visible to this process now.
    os.environ["PATH"] = str(bindir) + os.pathsep + os.environ.get("PATH", "")
    if _which("snyk"):
        log(f"[snyk] standalone CLI ready → {target}")
        return True
    log(f"[snyk] installed to {target}, but {bindir} is not on PATH. "
        f"Add it to your shell profile (e.g. export PATH=\"{bindir}:$PATH\").")
    return target.exists()


# ── Environment checks ────────────────────────────────────────────────────────
@dataclass
class CheckResult:
    name: str; ok: bool; detail: str = ""; fixable: bool = False


def check_python() -> CheckResult:
    v = sys.version_info
    return CheckResult("Python ≥ 3.9",
                       (v.major, v.minor) >= (3, 9),
                       f"Python {v.major}.{v.minor}.{v.micro}")


def _check_tool(label: str, cmd: str) -> CheckResult:
    real = "npm.cmd" if (cmd == "npm" and os.name == "nt") else cmd
    if not _which(cmd):
        return CheckResult(label, False, "not found in PATH", fixable=True)
    try:
        r = _run([real, "--version"])
        return CheckResult(label, r.returncode == 0,
                           (r.stdout or "").strip(), fixable=True)
    except Exception as e:
        return CheckResult(label, False, str(e), fixable=True)


def check_node() -> CheckResult: return _check_tool("Node.js", "node")
def check_npm()  -> CheckResult: return _check_tool("npm", "npm")
def check_snyk() -> CheckResult: return _check_tool("Snyk CLI", "snyk")


def _snyk_cfg(key: str) -> str:
    try:
        v = (_run(["snyk", "config", "get", key]).stdout or "").strip()
        return "" if v.lower() in ("", "undefined", "null", "not set") else v
    except Exception:
        return ""


def check_auth() -> CheckResult:
    if not _which("snyk"):
        return CheckResult("Snyk auth", False, "Snyk CLI missing")
    if tok := _snyk_cfg("api"):
        m = tok[:4] + "…" + tok[-4:] if len(tok) > 8 else "set"
        return CheckResult("Snyk auth", True, f"token: {m}", fixable=True)
    if _snyk_cfg("INTERNAL_OAUTH_TOKEN_STORAGE"):
        return CheckResult("Snyk auth", True, "SSO/OAuth active", fixable=True)
    try:
        r = _run(["snyk", "whoami", "--experimental"], timeout=30)
        if r.returncode == 0:
            lines = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
            label = next((ln for ln in lines if ln.strip()), "authenticated")
            return CheckResult("Snyk auth", True, label[:40], fixable=True)
    except Exception:
        pass
    return CheckResult("Snyk auth", False, "not authenticated", fixable=True)


# ── Installers ────────────────────────────────────────────────────────────────
def install_node(log: Callable[[str], None]) -> bool:
    if _which("node") and _which("npm"):
        log("[node] already installed"); return True

    if IS_WIN:
        if not _which("winget"):
            log("[node] install Node.js LTS from https://nodejs.org/"); return False
        log("[node] installing via winget…")
        r = _run(["winget", "install", "--id", "OpenJS.NodeJS.LTS", "-e",
                  "--silent", "--accept-package-agreements",
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

    # Linux
    mgr = _linux_pkg_mgr()
    if not mgr:
        log("[node] no supported package manager found. Install Node.js LTS via "
            "your distro or nvm (https://github.com/nvm-sh/nvm).")
        return False
    name, install_args = mgr
    # Debian/Ubuntu ship the binary as 'nodejs'; most distros also provide 'npm'.
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


def install_snyk(log: Callable[[str], None]) -> bool:
    if _which("snyk"):
        log("[snyk] already installed"); return True

    # Preferred path: npm (works on every OS when Node is present).
    if _which("npm"):
        npm = "npm.cmd" if IS_WIN else "npm"
        log("[snyk] npm install -g snyk")
        r = _run_tls([npm, "install", "-g", "snyk"], log=log, timeout=1800)
        if r.stdout: log(r.stdout)
        if r.stderr: log(r.stderr)
        _augment_path()
        if _which("snyk"):
            return True
        log("[snyk] npm install did not expose 'snyk' on PATH; trying fallback…")

    # No npm (or it failed): use a native package manager where possible.
    if IS_MAC and _brew():
        brew = _brew()
        log("[snyk] installing via Homebrew (brew install snyk-cli)…")
        r = _run([brew, "install", "snyk-cli"], timeout=1800)
        if r.returncode != 0:                      # older tap name
            r = _run([brew, "install", "snyk"], timeout=1800)
        if r.stdout: log(r.stdout.strip()[-2000:])
        if r.stderr: log(r.stderr.strip()[-2000:])
        _augment_path()
        if _which("snyk"):
            return True

    if IS_WIN and _which("winget"):
        log("[snyk] installing via winget (Snyk.SnykCLI)…")
        r = _run(["winget", "install", "--id", "Snyk.SnykCLI", "-e", "--silent",
                  "--accept-package-agreements", "--accept-source-agreements"],
                 timeout=1800)
        log((r.stdout or "") + (r.stderr or ""))
        if _which("snyk"):
            return True

    # Universal npm-free fallback: official standalone binary.
    log("[snyk] falling back to the standalone Snyk CLI binary…")
    return _install_standalone_snyk(log)


def start_snyk_auth(log: Callable[[str], None]) -> subprocess.Popen:
    log("[auth] launching `snyk auth` — browser will open shortly.")
    kwargs: dict = {}
    if IS_WIN:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    return subprocess.Popen([_snyk_bin(), "auth"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace",
                            **kwargs)


# ── JSON helpers ──────────────────────────────────────────────────────────────
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


# ── Python sandbox helper ─────────────────────────────────────────────────────
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


# ── Core scan runner ──────────────────────────────────────────────────────────
def _snyk_json_scan(args, *, target, out_dir, out_name, log, env=None,
                    timeout=1800, write_raw=False,
                    count_label="") -> tuple[Any, Path]:
    log(f"[scan] $ snyk {' '.join(args[1:])}  (cwd={target})")
    r = _run(args, cwd=target, env=env, timeout=timeout)
    if r.stderr:
        log(r.stderr.strip()[-2000:])
    data = _parse_json_loose(r.stdout or "")
    out_path = out_dir / out_name
    out_path.write_text(
        r.stdout or "" if write_raw else json.dumps(data, indent=2),
        encoding="utf-8")
    if count_label:
        log(f"[scan] {count_label} total vulnerabilities: {_count_vulns(data)}")
    log(f"[scan] raw JSON → {out_path}")
    return data, out_path


def run_snyk_test(target: Path, out_dir: Path,
                  log: Callable[[str], None]) -> tuple[Any, Path]:
    """SCA scan via `snyk test --all-projects`."""
    sb_env = _prepare_pip_sandbox(target, log)
    args = ["snyk", "test", "--all-projects", "--detection-depth=10",
            "--strict-out-of-sync=false", "--skip-unresolved", "--json"]
    return _snyk_json_scan(args, target=target, out_dir=out_dir,
                           out_name="snyk_test.json", log=log, env=sb_env,
                           count_label="SCA")


def run_snyk_code(target: Path, out_dir: Path,
                  log: Callable[[str], None]) -> tuple[Any, Path]:
    """SAST scan via `snyk code test`."""
    return _snyk_json_scan(["snyk", "code", "test", "--json"],
                           target=target, out_dir=out_dir,
                           out_name="snyk_code.json",
                           log=log, write_raw=True)


# ── SARIF / merged-JSON exporters ─────────────────────────────────────────────
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


def export_sarif(out_dir: Path) -> Optional[Path]:
    """Build a single SARIF 2.1.0 log from every scanner's raw output in
    out_dir. Returns the path, or None if nothing could be assembled."""
    runs: list[dict] = []

    def _load(name):
        f = out_dir / name
        if not f.exists(): return None
        try: return json.loads(f.read_text(encoding="utf-8"))
        except Exception: return None

    sca = _load("snyk_test.json")
    if sca is not None:
        sca_findings = _collect_sca_findings(sca)
        if sca_findings:
            runs.append(_sarif_run("Snyk Open Source (SCA)", sca_findings))

    # snyk code --json already emits SARIF — merge its runs verbatim.
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
    """One flat JSON array of all non-SAST findings (DAST + API + SCA).
    Snyk Code SARIF stays in snyk_code.json."""
    merged: list[dict] = []

    def _load(name):
        f = out_dir / name
        if not f.exists(): return None
        try: return json.loads(f.read_text(encoding="utf-8"))
        except Exception: return None

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
