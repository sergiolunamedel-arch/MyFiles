from __future__ import annotations

# ── secrets_scanner.py ────────────────────────────────────────────────────────
# Standalone secret-scanning module for the Vulnerability Scanner.
#
# What it does
#   • On startup the app calls ensure_git_secrets() which auto-downloads the real
#     AWS `git-secrets` script from GitHub into a local cache (best effort) so the
#     "se auto descarga lo necesario al abrir el programa" requirement is met.
#   • scan_path() walks a target folder and flags hard-coded credentials. It uses
#     the real git-secrets binary when the target is a git repo and the tool +
#     git/bash are available, and ALWAYS runs a built-in, cross-platform regex
#     engine (modelled on git-secrets' default AWS provider plus common token
#     formats) so results are produced on Windows / macOS / Linux regardless.
#   • write_secrets_report() emits a *separate* self-contained HTML file
#     (secrets.html) + secrets.json where the found secrets can be reviewed.
#
# Pure standard library only (urllib) — safe to import before heavy deps exist.

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

# ── Platform ──────────────────────────────────────────────────────────────────
IS_WIN   = os.name == "nt"
IS_MAC   = sys.platform == "darwin"
IS_LINUX = not IS_WIN and not IS_MAC

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

GIT_SECRETS_RAW_URL = (
    "https://raw.githubusercontent.com/awslabs/git-secrets/master/git-secrets"
)

# Where we cache the downloaded git-secrets script.
def _cache_dir() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or
                os.environ.get("XDG_CACHE_HOME") or
                (Path.home() / ".cache"))
    d = base / "vuln-scanner" / "git-secrets"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except Exception:
        d = Path(tempfile.gettempdir()) / "vuln-scanner-git-secrets"
        d.mkdir(parents=True, exist_ok=True)
    return d


def _log(cb: Optional[Callable[[str], None]], msg: str) -> None:
    if cb:
        try: cb(msg)
        except Exception: pass


# ── Built-in providers (modelled on git-secrets defaults + common formats) ─────
# Each: (rule, secret_type, severity, compiled regex)
def _p(pattern: str, flags: int = 0) -> "re.Pattern[str]":
    return re.compile(pattern, flags)

_PROVIDERS: list[tuple[str, str, str, "re.Pattern[str]"]] = [
    ("aws-access-key-id", "AWS Access Key ID", "critical",
     _p(r"(?<![A-Z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Z0-9])")),
    ("aws-secret-access-key", "AWS Secret Access Key", "critical",
     _p(r"(?i)aws.{0,24}?(?:secret|private).{0,24}?['\"`]([0-9a-zA-Z/+]{40})['\"`]")),
    ("aws-session-token", "AWS Session Token", "high",
     _p(r"(?i)aws.{0,24}?session.{0,24}?token.{0,4}?['\"`]([0-9a-zA-Z/+=]{100,})['\"`]")),
    ("private-key", "Private key block", "critical",
     _p(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    ("gcp-api-key", "Google API key", "high",
     _p(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("gcp-oauth", "Google OAuth client id", "medium",
     _p(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b")),
    ("github-token", "GitHub token", "high",
     _p(r"\bgh[pousr]_[0-9A-Za-z]{36,255}\b")),
    ("slack-token", "Slack token", "high",
     _p(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")),
    ("slack-webhook", "Slack webhook URL", "medium",
     _p(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{30,}")),
    ("stripe-secret", "Stripe live secret key", "critical",
     _p(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b")),
    ("twilio-key", "Twilio API key", "high",
     _p(r"\bSK[0-9a-fA-F]{32}\b")),
    ("sendgrid-key", "SendGrid API key", "high",
     _p(r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b")),
    ("jwt", "JSON Web Token", "medium",
     _p(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("basic-auth-url", "Credentials embedded in URL", "high",
     _p(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]{1,64}:([^/\s:@]{3,64})@")),
    ("generic-secret", "Generic hard-coded secret", "medium",
     _p(r"(?i)\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password|pwd)\b\s*[:=]\s*['\"`]([^'\"`\s]{12,128})['\"`]")),
]

# Strong, unambiguous placeholder markers — a hit is downgraded to "low" only
# when the matched token itself (not the whole line) contains one of these.
_EXAMPLE_MARKERS = (
    "EXAMPLE", "your-api-key", "your_api_key", "changeme", "change-me",
    "placeholder", "dummy", "redacted", "xxxxxxxx", "test-key", "testkey",
    "notreal", "fakekey", "sample",
)

# Directories / files never worth scanning.
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
    "venv", ".venv", "env", ".env.d", "__pycache__", ".mypy_cache",
    ".pytest_cache", "dist", "build", ".idea", ".vscode", ".gradle",
    "site-packages", "target", ".next", ".nuxt", "coverage", ".tox",
    "Reports", "reports",
}
_SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".pdf", ".zip", ".gz", ".tar", ".tgz", ".bz2", ".7z", ".rar",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".ogg", ".flac",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".class", ".jar", ".war", ".so", ".dll", ".dylib", ".exe", ".bin",
    ".pyc", ".pyo", ".o", ".a", ".lib", ".obj", ".wasm",
    ".lock",
}
_MAX_BYTES = 1_500_000   # skip files larger than ~1.5 MB
_BINARY_SNIFF = 4096


# ── Redaction ─────────────────────────────────────────────────────────────────
def redact(secret: str, keep_head: int = 4, keep_tail: int = 2) -> str:
    s = secret.strip()
    if len(s) <= keep_head + keep_tail:
        return "•" * len(s)
    return f"{s[:keep_head]}{'•' * max(4, len(s) - keep_head - keep_tail)}{s[-keep_tail:]}"


def _looks_like_example(text: str) -> bool:
    up = text.upper()
    return any(m.upper() in up for m in _EXAMPLE_MARKERS)


# ── git-secrets bootstrap (auto-download) ─────────────────────────────────────
def ensure_git_secrets(log: Optional[Callable[[str], None]] = None) -> dict:
    """Best-effort download of the real git-secrets script into the cache.

    Returns a status dict: {available, method, path, has_git, has_bash, note}.
    Scanning never depends on this succeeding — the built-in engine always runs.
    """
    status: dict[str, Any] = {
        "available": False, "method": "builtin", "path": None,
        "has_git": bool(shutil.which("git")),
        "has_bash": bool(shutil.which("bash")) or IS_MAC or IS_LINUX,
        "note": "",
    }
    target = _cache_dir() / "git-secrets"

    if target.exists() and target.stat().st_size > 1000:
        status.update(available=True, method="git-secrets", path=str(target),
                      note="cached")
        _log(log, f"[secrets] git-secrets ready (cached): {target}")
        return status

    _log(log, "[secrets] downloading git-secrets from GitHub…")
    try:
        import urllib.request
        req = urllib.request.Request(
            GIT_SECRETS_RAW_URL,
            headers={"User-Agent": "vuln-scanner/1.0"})
        with urllib.request.urlopen(req, timeout=25) as resp:  # nosec - fixed URL
            data = resp.read()
        if not data or len(data) < 1000:
            raise ValueError("downloaded script looks empty")
        target.write_bytes(data)
        if not IS_WIN:
            try: os.chmod(target, 0o755)
            except Exception: pass
        status.update(available=True, method="git-secrets", path=str(target),
                      note="downloaded")
        _log(log, f"[secrets] git-secrets downloaded → {target} "
                  f"({len(data)//1024} KB)")
    except Exception as e:
        status["note"] = f"download failed: {e!r} — using built-in engine"
        _log(log, f"[secrets] git-secrets download failed ({e!r}); "
                  f"built-in engine will be used.")
    return status


# ── Real git-secrets execution (optional, when environment allows) ────────────
def _run_git_secrets(script: Path, target: Path,
                     log: Optional[Callable[[str], None]] = None) -> list[dict]:
    """Try to run the downloaded git-secrets against a git repo.

    Returns findings or [] on any problem. Heavily defensive: this is a bonus
    layer on top of the always-on built-in engine.
    """
    if not (target / ".git").exists():
        return []
    git = shutil.which("git")
    if not git:
        return []
    bash = shutil.which("bash")
    # Register AWS provider into an isolated config, then scan the repo.
    findings: list[dict] = []
    try:
        env = os.environ.copy()
        tmp_cfg = _cache_dir() / "gs_global.gitconfig"
        env["GIT_CONFIG_GLOBAL"] = str(tmp_cfg)        # git ≥ 2.32
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        runner = [bash, str(script)] if bash else [str(script)]
        # --register-aws loads the canonical AWS patterns into the global config.
        subprocess.run(runner + ["--register-aws", "--global"],
                       cwd=str(target), env=env, timeout=60,
                       capture_output=True, text=True)
        proc = subprocess.run(runner + ["--scan", "-r", "."],
                              cwd=str(target), env=env, timeout=300,
                              capture_output=True, text=True)
        # git-secrets prints "path:line:matched-text" to stderr on a hit.
        out = (proc.stderr or "") + "\n" + (proc.stdout or "")
        for line in out.splitlines():
            m = re.match(r"^(.*?):(\d+):(.*)$", line)
            if not m:
                continue
            fp, ln, txt = m.group(1), int(m.group(2)), m.group(3)
            if "Possible mistakes" in txt or not txt.strip():
                continue
            sev = "low" if _looks_like_example(txt) else "critical"
            findings.append({
                "file": fp, "line": ln, "severity": sev,
                "rule": "git-secrets/aws", "title": "AWS credential (git-secrets)",
                "secret_type": "AWS credential", "match": redact(txt.strip()),
                "engine": "git-secrets",
            })
    except Exception as e:
        _log(log, f"[secrets] git-secrets run skipped: {e!r}")
        return []
    if findings:
        _log(log, f"[secrets] git-secrets reported {len(findings)} hit(s).")
    return findings


# ── Built-in cross-platform engine ────────────────────────────────────────────
def _is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(_BINARY_SNIFF)
        return b"\x00" in chunk
    except Exception:
        return True


def _iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS
                       and not d.startswith(".") or d in (".github",)]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext in _SKIP_EXT:
                continue
            yield Path(dirpath) / name


def _scan_builtin(target: Path, log: Optional[Callable[[str], None]] = None,
                  cancel=None) -> tuple[list[dict], int]:
    findings: list[dict] = []
    scanned = 0
    seen: set[tuple] = set()
    for fp in _iter_files(target):
        if cancel is not None and getattr(cancel, "is_set", lambda: False)():
            _log(log, "[secrets] scan cancelled.")
            break
        try:
            if fp.stat().st_size > _MAX_BYTES or _is_binary(fp):
                continue
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        scanned += 1
        rel = str(fp.relative_to(target)) if _is_relative(fp, target) else str(fp)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line) > 4000:
                continue
            for rule, stype, sev, rx in _PROVIDERS:
                m = rx.search(line)
                if not m:
                    continue
                raw = m.group(m.lastindex) if m.lastindex else m.group(0)
                eff_sev = "low" if _looks_like_example(raw) else sev
                key = (rel, lineno, rule, raw[:12])
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "file": rel, "line": lineno, "severity": eff_sev,
                    "rule": rule, "title": stype, "secret_type": stype,
                    "match": redact(raw),
                    "context": redact_line(line, raw),
                    "engine": "builtin",
                })
    return findings, scanned


def _is_relative(p: Path, root: Path) -> bool:
    try:
        p.relative_to(root); return True
    except Exception:
        return False


def redact_line(line: str, secret: str) -> str:
    snippet = line.strip()
    if len(snippet) > 160:
        idx = snippet.find(secret.strip())
        if idx >= 0:
            start = max(0, idx - 40)
            snippet = ("…" if start else "") + snippet[start:idx + len(secret) + 40] + "…"
        else:
            snippet = snippet[:160] + "…"
    try:
        snippet = snippet.replace(secret.strip(), redact(secret))
    except Exception:
        pass
    return snippet


# ── Public scan entry point ───────────────────────────────────────────────────
def scan_path(target, log: Optional[Callable[[str], None]] = None, *,
              cancel=None, git_secrets_status: Optional[dict] = None) -> dict:
    target = Path(target).resolve()
    _log(log, f"[secrets] scanning {target}")
    t0 = time.time()
    findings: list[dict] = []

    # Bonus layer: real git-secrets if available and target is a repo.
    gss = git_secrets_status or {}
    script = gss.get("path")
    if script and Path(script).exists():
        try:
            findings.extend(_run_git_secrets(Path(script), target, log))
        except Exception as e:
            _log(log, f"[secrets] git-secrets layer error: {e!r}")

    # Always-on built-in engine.
    builtin, scanned = _scan_builtin(target, log, cancel=cancel)

    # Merge (avoid double counting same file/line/rule).
    seen = {(f["file"], f["line"], f["rule"]) for f in findings}
    for f in builtin:
        if (f["file"], f["line"], f["rule"]) not in seen:
            findings.append(f)

    findings.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 99),
                                 x["file"], x["line"]))
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    dt = time.time() - t0
    engine = "git-secrets + built-in" if (script and Path(script).exists()) else "built-in"
    _log(log, f"[secrets] done — {len(findings)} finding(s) across "
              f"{scanned} file(s) in {dt:.1f}s")
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": str(target), "engine": engine,
        "scanned_files": scanned, "elapsed": round(dt, 2),
        "counts": counts, "total": len(findings), "findings": findings,
    }


# ── Separate report file (HTML + JSON) ────────────────────────────────────────
_SECRETS_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Secrets Report — {generated_at}</title><style>
:root{{--bg:#0d1b2a;--panel:#13243a;--bd:#21364f;--tx:#e8eef7;--mu:#90a4bd;
--ac:#F5A800;--crit:#ff5d6c;--high:#ff944d;--med:#ffd23f;--low:#5fe0a0}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--tx);
font:14px/1.55 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}}
.shell{{max-width:1280px;margin:0 auto;padding:30px clamp(16px,4vw,48px) 80px}}
.top{{display:flex;align-items:center;gap:14px;margin-bottom:22px;flex-wrap:wrap}}
.logo{{width:42px;height:42px;border-radius:11px;background:var(--ac);color:#111;
display:grid;place-items:center;font-weight:800;font-size:20px}}
h1{{margin:0;font-size:22px}}.sub{{color:var(--mu);font-size:12px}}
.pill{{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}}
.tag{{background:var(--panel);border:1px solid var(--bd);border-radius:999px;
padding:6px 12px;font-size:12px;color:var(--mu)}}.tag b{{color:var(--tx)}}
.kpis{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:8px 0 26px}}
@media(max-width:760px){{.kpis{{grid-template-columns:repeat(2,1fr)}}}}
.kpi{{background:var(--panel);border:1px solid var(--bd);border-left:4px solid var(--ac);
border-radius:12px;padding:16px}}.kpi .l{{color:var(--mu);font-size:11px;
text-transform:uppercase;letter-spacing:.1em}}.kpi .v{{font-size:30px;font-weight:800;margin-top:6px}}
.kpi.critical{{border-left-color:var(--crit)}}.kpi.high{{border-left-color:var(--high)}}
.kpi.medium{{border-left-color:var(--med)}}.kpi.low{{border-left-color:var(--low)}}
table{{width:100%;border-collapse:collapse;background:var(--panel);
border:1px solid var(--bd);border-radius:12px;overflow:hidden;font-size:13px}}
th{{text-align:left;color:var(--mu);font-size:11px;text-transform:uppercase;
letter-spacing:.07em;padding:12px 14px;border-bottom:1px solid var(--bd)}}
td{{padding:11px 14px;border-bottom:1px solid var(--bd);vertical-align:top}}
tr:last-child td{{border-bottom:0}}tr:hover td{{background:#16294250}}
code{{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0b1626;
border:1px solid var(--bd);border-radius:6px;padding:1px 6px;font-size:12px}}
.sev{{display:inline-block;padding:3px 10px;border-radius:999px;font-size:11px;
font-weight:800;text-transform:uppercase}}
.sev.critical{{background:#ff5d6c22;color:var(--crit)}}.sev.high{{background:#ff944d22;color:var(--high)}}
.sev.medium{{background:#ffd23f22;color:var(--med)}}.sev.low{{background:#5fe0a022;color:var(--low)}}
.empty{{text-align:center;padding:48px;color:var(--mu);background:var(--panel);
border:1px dashed var(--bd);border-radius:12px}}
.note{{margin:18px 0;color:var(--mu);font-size:12px}}
footer{{text-align:center;color:var(--mu);font-size:12px;padding:34px 0 0}}
</style></head><body><div class="shell">
<div class="top"><div class="logo">🔑</div>
<div><h1>Secrets Report</h1><div class="sub">git-secrets · hard-coded credential scan</div></div>
<div class="pill"><span class="tag">Engine <b>{engine}</b></span>
<span class="tag">Target <b>{target}</b></span>
<span class="tag">Files <b>{scanned_files}</b></span>
<span class="tag">Generated <b>{generated_at}</b></span></div></div>
<div class="kpis">
<div class="kpi"><div class="l">Total</div><div class="v">{total}</div></div>
<div class="kpi critical"><div class="l">Critical</div><div class="v">{c_critical}</div></div>
<div class="kpi high"><div class="l">High</div><div class="v">{c_high}</div></div>
<div class="kpi medium"><div class="l">Medium</div><div class="v">{c_medium}</div></div>
<div class="kpi low"><div class="l">Low</div><div class="v">{c_low}</div></div>
</div>
{body}
<p class="note">Matched secrets are redacted. Treat any flagged credential as
compromised: rotate it and purge it from version-control history.</p>
<footer>Vulnerability Scanner · Secrets module · {generated_at}</footer>
</div></body></html>"""


def render_secrets_html(result: dict) -> str:
    import html as _html
    findings = result.get("findings", [])
    if findings:
        rows = []
        for f in findings:
            rows.append(
                "<tr>"
                f"<td><span class='sev {f['severity']}'>{f['severity']}</span></td>"
                f"<td>{_html.escape(f.get('secret_type', f.get('rule','')))}</td>"
                f"<td><code>{_html.escape(str(f['file']))}</code></td>"
                f"<td>{f.get('line','?')}</td>"
                f"<td><code>{_html.escape(str(f.get('match','')))}</code></td>"
                f"<td><code>{_html.escape(str(f.get('engine','')))}</code></td>"
                "</tr>")
        body = ("<table><thead><tr><th>Severity</th><th>Type</th><th>File</th>"
                "<th>Line</th><th>Secret (redacted)</th><th>Engine</th></tr></thead>"
                "<tbody>" + "".join(rows) + "</tbody></table>")
    else:
        body = ("<div class='empty'>No hard-coded secrets detected. "
                "Nothing to rotate — nice.</div>")
    counts = result.get("counts", {})
    return _SECRETS_HTML.format(
        generated_at=result.get("generated_at", ""),
        engine=result.get("engine", ""),
        target=_safe(result.get("target", "")),
        scanned_files=result.get("scanned_files", 0),
        total=result.get("total", 0),
        c_critical=counts.get("critical", 0), c_high=counts.get("high", 0),
        c_medium=counts.get("medium", 0), c_low=counts.get("low", 0),
        body=body)


def _safe(s: str) -> str:
    import html as _html
    return _html.escape(str(s))


def write_secrets_report(result: dict, out_dir) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "secrets.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8")
    html_path = out_dir / "secrets.html"
    html_path.write_text(render_secrets_html(result), encoding="utf-8")
    return html_path


# Allow quick manual testing: python secrets_scanner.py <folder>
if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else "."
    st = ensure_git_secrets(print)
    res = scan_path(tgt, print, git_secrets_status=st)
    out = write_secrets_report(res, Path(tgt) / "_secrets_out")
    print("report:", out)
