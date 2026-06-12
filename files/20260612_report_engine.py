from __future__ import annotations

# ── report_engine.py ─────────────────────────────────────────────────────────
# Standalone report module extracted from Snyk_Scanner_GUI.py.
# Contains: data normalizers, context builder, CSV exporter, HTML template,
#           and HTML renderer.
# Both files must live in the same directory (or report_engine on sys.path).

import csv, json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Template

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# ── Report normalizers ────────────────────────────────────────────────────────
def _norm_test(data: Any) -> list[dict]:
    if data is None: return []
    out = []
    for p in (data if isinstance(data, list) else [data]):
        if not isinstance(p, dict): continue
        if p.get("error"):
            out.append({"project": p.get("path") or "(unknown)", "error": p["error"], "issues": []})
            continue
        issues = []
        for v in (p.get("vulnerabilities") or []):
            ids = v.get("identifiers", {}) or {}
            issues.append({
                "severity": (v.get("severity") or "low").lower(),
                "title":    v.get("title") or v.get("id") or "Vulnerability",
                "package":  f"{v.get('packageName','?')}@{v.get('version','?')}",
                "id":       v.get("id"),
                "cve":      ", ".join(ids.get("CVE", []) or []),
                "cwe":      ", ".join(ids.get("CWE", []) or []),
                "fixedIn":  ", ".join(v.get("fixedIn") or []) or "—",
                "path":     " > ".join((v.get("from") or [])[1:]) or "(direct)",
                "url":      v.get("url") or "",
                "description": (v.get("description") or "")[:1200],
            })
        issues.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
        out.append({
            "project":     p.get("projectName") or p.get("displayTargetFile") or p.get("path") or "(project)",
            "summary":     p.get("summary") or "",
            "uniqueCount": p.get("uniqueCount") or len(issues),
            "issues":      issues,
        })
    return out

def _norm_code(data: Any) -> list[dict]:
    if data is None: return []
    runs: list = []
    if isinstance(data, dict): runs = data.get("runs") or []
    elif isinstance(data, list):
        for d in data:
            if isinstance(d, dict): runs.extend(d.get("runs") or [])
    by_file: dict[str, list[dict]] = {}
    for blk in runs:
        tool  = (blk.get("tool") or {}).get("driver") or {}
        rules = {r.get("id"): r for r in (tool.get("rules") or [])}
        for result in (blk.get("results") or []):
            level = (result.get("level") or "warning").lower()
            sev   = {"error": "high", "warning": "medium", "note": "low"}.get(level, "medium")
            props = result.get("properties") or {}
            sp = (props.get("issueSeverity") or props.get("security-severity") or "").lower()
            if sp in SEVERITY_ORDER: sev = sp
            elif sp:
                try:
                    s = float(sp)
                    sev = "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
                except ValueError: pass
            rule_id = result.get("ruleId") or "rule"
            rule    = rules.get(rule_id, {})
            message = ((result.get("message") or {}).get("text")
                       or rule.get("shortDescription", {}).get("text") or rule_id)
            cwe = [t.upper() for t in (rule.get("properties") or {}).get("tags", []) or []
                   if isinstance(t, str) and t.lower().startswith("cwe")]
            for loc in (result.get("locations") or [{}]):
                phys    = (loc.get("physicalLocation") or {}) if loc else {}
                region  = phys.get("region") or {}
                ctx     = phys.get("contextRegion") or {}
                snippet = ((ctx.get("snippet") or region.get("snippet") or {}).get("text")) or ""
                fp      = (phys.get("artifactLocation") or {}).get("uri") or "(unknown file)"
                by_file.setdefault(fp, []).append({
                    "severity": sev, "rule": rule_id,
                    "title":    rule.get("name") or rule.get("shortDescription", {}).get("text") or rule_id,
                    "message":  message, "line": region.get("startLine") or "?",
                    "cwe":      ", ".join(sorted(set(cwe))), "snippet": snippet,
                })
    result_list = []
    for f, issues in by_file.items():
        issues.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
        result_list.append({"file": f, "issues": issues})
    result_list.sort(key=lambda x: x["file"])
    return result_list


# ── Report builder ────────────────────────────────────────────────────────────
def build_context(test_data, code_data, target, snyk_version,
                  dast_data=None, api_data=None, secrets_data=None) -> dict:
    projects  = _norm_test(test_data)
    files     = _norm_code(code_data)
    counts    = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    sca_total = code_total = dast_total = api_total = secrets_total = 0
    for p in projects:
        for i in p["issues"]:
            counts[i["severity"]] = counts.get(i["severity"], 0) + 1; sca_total += 1
    for f in files:
        for i in f["issues"]:
            counts[i["severity"]] = counts.get(i["severity"], 0) + 1; code_total += 1
    dast_findings = (dast_data or {}).get("findings", [])
    for d in dast_findings:
        counts[d.get("severity", "low")] = counts.get(d.get("severity", "low"), 0) + 1
        dast_total += 1
    api_findings = (api_data or {}).get("findings", [])
    for d in api_findings:
        counts[d.get("severity", "low")] = counts.get(d.get("severity", "low"), 0) + 1
        api_total += 1
    # Secrets findings — normalise from secrets_scanner result dict or raw list
    secrets_findings: list[dict] = []
    if secrets_data:
        raw = secrets_data.get("findings", []) if isinstance(secrets_data, dict) else []
        for s in raw:
            sev = s.get("severity", "high")
            counts[sev] = counts.get(sev, 0) + 1
            secrets_total += 1
            secrets_findings.append({
                "severity":    sev,
                "secret_type": s.get("secret_type") or s.get("title") or s.get("rule", ""),
                "rule":        s.get("rule", ""),
                "file":        s.get("file", ""),
                "line":        s.get("line", "?"),
                "match":       s.get("match", ""),  # already redacted
                "engine":      s.get("engine", ""),
                "context":     s.get("context", ""),
                # Industry standard CWE for hard-coded credentials
                "cwe":         s.get("cwe", "CWE-798"),
            })
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": str(target), "snyk_version": snyk_version,
        "counts": counts,
        "total":          sca_total + code_total + dast_total + api_total + secrets_total,
        "sca_total":      sca_total,     "code_total":    code_total,
        "dast_total":     dast_total,    "api_total":     api_total,
        "secrets_total":  secrets_total,
        "projects":       projects,      "files":         files,
        "dast": {"target":            (dast_data or {}).get("target", ""),
                 "profile":           (dast_data or {}).get("profile", ""),
                 "pages_visited":     (dast_data or {}).get("pages_visited", 0),
                 "forms_discovered":  (dast_data or {}).get("forms_discovered", 0),
                 "findings":          dast_findings},
        "api":  {"target":            (api_data or {}).get("target", ""),
                 "spec_source":       (api_data or {}).get("spec_source", ""),
                 "profile":           (api_data or {}).get("profile", ""),
                 "endpoints_tested":  (api_data or {}).get("endpoints_tested", 0),
                 "endpoints_total":   (api_data or {}).get("endpoints_total", 0),
                 "findings":          api_findings},
        "secrets": {
            "engine":         (secrets_data or {}).get("engine", "") if isinstance(secrets_data, dict) else "",
            "scanned_files":  (secrets_data or {}).get("scanned_files", 0) if isinstance(secrets_data, dict) else 0,
            "elapsed":        (secrets_data or {}).get("elapsed", 0) if isinstance(secrets_data, dict) else 0,
            "findings":       secrets_findings,
        },
    }

def _ts() -> str: return datetime.now().strftime("%Y%m%d_%H%M%S")

def export_csv(ctx: dict, path: Path) -> Path:
    """Export per-scan-type CSVs with industry-standard columns inside a ZIP,
    plus a unified summary sheet.

    SCA  : OWASP Dependency-Check / Snyk SCA field set
    SAST : OWASP ASVS / SARIF / CWE field set
    DAST : OWASP ZAP / Burp field set
    API  : OWASP API Security Top-10 field set
    Secrets: NIST SP 800-53 / CWE-798 field set
    """
    import csv, zipfile, io

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path.parent.mkdir(parents=True, exist_ok=True)

    # ── helpers ──────────────────────────────────────────────────────────────
    def _w(buf: io.StringIO, header: list[str], rows: list[list]) -> None:
        w = csv.writer(buf)
        w.writerow(header)
        w.writerows(rows)

    # ── 1. SCA — Software Composition Analysis ───────────────────────────────
    # Columns align with OWASP Dependency-Check CSV export, Snyk SCA, and
    # GitHub Dependabot advisory format.
    SCA_HEADER = [
        "scan_type", "project", "severity", "cvss_score",
        "vulnerable_package", "installed_version", "fixed_version",
        "vulnerability_id", "cve", "cwe", "dependency_path",
        "transitive", "description_preview", "advisory_url",
    ]
    sca_rows: list[list] = []
    for p in ctx.get("projects", []):
        for i in p["issues"]:
            pkg_raw  = i.get("package", "")          # "name@version"
            pkg_name = pkg_raw.split("@")[0] if "@" in pkg_raw else pkg_raw
            pkg_ver  = pkg_raw.split("@")[1] if "@" in pkg_raw else ""
            dep_path = i.get("path", "(direct)")
            transitive = "No" if dep_path in ("(direct)", "") else "Yes"
            sca_rows.append([
                "SCA",
                p.get("project", ""),
                i.get("severity", "").upper(),
                "",                                   # cvss_score — enrichable
                pkg_name,
                pkg_ver,
                i.get("fixedIn", "—"),
                i.get("id", ""),
                i.get("cve", ""),
                i.get("cwe", ""),
                dep_path,
                transitive,
                (i.get("description", "") or "")[:200],
                i.get("url", ""),
            ])

    # ── 2. SAST — Static Application Security Testing ───────────────────────
    # Columns align with SARIF 2.1 (ruleId / physicalLocation / region),
    # OWASP ASVS, and Checkmarx/Fortify CSV exports.
    SAST_HEADER = [
        "scan_type", "file_path", "severity", "rule_id", "rule_name",
        "line_start", "cwe", "owasp_category", "message",
        "code_snippet_preview",
    ]
    sast_rows: list[list] = []
    _SAST_OWASP = {
        "CWE-79":  "A03 Injection",
        "CWE-89":  "A03 Injection",
        "CWE-94":  "A03 Injection",
        "CWE-78":  "A03 Injection",
        "CWE-77":  "A03 Injection",
        "CWE-918": "A10 SSRF",
        "CWE-611": "A05 Security Misconfiguration",
        "CWE-22":  "A01 Broken Access Control",
        "CWE-23":  "A01 Broken Access Control",
        "CWE-352": "A01 Broken Access Control",
        "CWE-862": "A01 Broken Access Control",
        "CWE-863": "A01 Broken Access Control",
        "CWE-502": "A08 Insecure Deserialization",
        "CWE-327": "A02 Cryptographic Failures",
        "CWE-326": "A02 Cryptographic Failures",
        "CWE-330": "A02 Cryptographic Failures",
        "CWE-798": "A07 Identification & Authentication",
        "CWE-259": "A07 Identification & Authentication",
        "CWE-287": "A07 Identification & Authentication",
        "CWE-200": "A02 Cryptographic Failures",
        "CWE-532": "A09 Security Logging Failures",
    }
    for f in ctx.get("files", []):
        for i in f["issues"]:
            cwe_raw   = i.get("cwe", "")
            owasp_cat = _SAST_OWASP.get(cwe_raw.split(",")[0].strip().upper(), "")
            snippet   = (i.get("snippet", "") or "").replace("\n", " ").strip()[:200]
            sast_rows.append([
                "SAST",
                f.get("file", ""),
                i.get("severity", "").upper(),
                i.get("rule", ""),
                i.get("title", ""),
                str(i.get("line", "")),
                cwe_raw,
                owasp_cat,
                (i.get("message", "") or "")[:300],
                snippet,
            ])

    # ── 3. DAST — Dynamic Application Security Testing ──────────────────────
    # Columns align with OWASP ZAP XML/CSV, Burp Suite Professional CSV, and
    # OWASP Testing Guide finding format.
    DAST_HEADER = [
        "scan_type", "severity", "owasp_api_top10", "category",
        "title", "url", "http_method", "parameter",
        "cwe", "evidence_preview", "solution_hint",
    ]
    _DAST_OWASP = {
        "auth":          "API2 Broken Authentication",
        "injection":     "API8 Injection",
        "csrf":          "API6 Mass Assignment",
        "headers":       "API7 Security Misconfiguration",
        "ssl":           "API7 Security Misconfiguration",
        "redirect":      "API3 Excessive Data Exposure",
        "xss":           "API8 Injection",
        "sqli":          "API8 Injection",
        "cors":          "API7 Security Misconfiguration",
        "info":          "API9 Improper Assets Management",
    }
    _DAST_SOLUTION = {
        "auth":      "Enforce strong authentication; implement MFA.",
        "injection": "Use parameterised queries / strict input validation.",
        "csrf":      "Add CSRF tokens; validate Origin/Referer headers.",
        "headers":   "Configure security headers (CSP, HSTS, X-Frame-Options).",
        "ssl":       "Enforce TLS 1.2+; disable weak ciphers and protocols.",
        "redirect":  "Whitelist allowed redirect targets; reject arbitrary URLs.",
        "xss":       "Encode output; implement strict CSP.",
        "sqli":      "Use parameterised queries / ORM; never concatenate user input.",
        "cors":      "Restrict CORS to trusted origins; avoid wildcard (*) for credentialed requests.",
        "info":      "Remove verbose error messages; suppress server version headers.",
    }
    dast_rows: list[list] = []
    for d in ctx.get("dast", {}).get("findings", []):
        cat = (d.get("category") or "").lower()
        dast_rows.append([
            "DAST",
            d.get("severity", "").upper(),
            _DAST_OWASP.get(cat, ""),
            d.get("category", ""),
            d.get("title", ""),
            d.get("url", ""),
            d.get("method", ""),
            d.get("param", ""),
            d.get("cwe", ""),
            (d.get("evidence", "") or "")[:300],
            _DAST_SOLUTION.get(cat, ""),
        ])

    # ── 4. API Security ──────────────────────────────────────────────────────
    # Columns align with OWASP API Security Top-10 2023 and Postman / 42Crunch
    # audit report format.
    API_HEADER = [
        "scan_type", "severity", "owasp_api_top10", "category",
        "title", "endpoint_url", "http_method", "parameter",
        "cwe", "authentication_required", "evidence_preview", "solution_hint",
    ]
    api_rows: list[list] = []
    for d in ctx.get("api", {}).get("findings", []):
        cat = (d.get("category") or "").lower()
        api_rows.append([
            "API",
            d.get("severity", "").upper(),
            _DAST_OWASP.get(cat, ""),
            d.get("category", ""),
            d.get("title", ""),
            d.get("url", ""),
            d.get("method", ""),
            d.get("param", ""),
            d.get("cwe", ""),
            d.get("auth_required", ""),
            (d.get("evidence", "") or "")[:300],
            _DAST_SOLUTION.get(cat, ""),
        ])

    # ── 5. Secrets — Hard-coded Credentials / Sensitive Data Exposure ────────
    # Columns align with GitLeaks CSV, Trufflehog v3 JSON output, and
    # NIST SP 800-53 IA-5 control evidence format.
    # CWE mapping: CWE-798 (Hard-coded Credentials), CWE-259 (Hard-coded
    # Password), CWE-321 (Hard-coded Crypto Key), CWE-522 (Insufficiently
    # Protected Credentials).
    _SECRET_CWE = {
        "private key block":             "CWE-321",
        "aws access key id":             "CWE-798",
        "aws secret access key":         "CWE-798",
        "aws session token":             "CWE-798",
        "generic hard-coded secret":     "CWE-259",
        "credentials embedded in url":   "CWE-522",
        "json web token":                "CWE-522",
    }
    SECRETS_HEADER = [
        "scan_type", "severity", "secret_type", "cwe", "owasp_top10",
        "file_path", "line_number", "commit_scope",
        "secret_match_redacted", "context_snippet",
        "engine", "remediation_action",
    ]
    secrets_rows: list[list] = []
    for s in ctx.get("secrets", {}).get("findings", []):
        stype = (s.get("secret_type") or s.get("rule", "")).strip().lower()
        cwe   = s.get("cwe") or _SECRET_CWE.get(stype, "CWE-798")
        secrets_rows.append([
            "Secrets",
            s.get("severity", "HIGH").upper(),
            s.get("secret_type") or s.get("rule", ""),
            cwe,
            "A07 Identification & Authentication Failures",  # OWASP Top 10 2021
            s.get("file", ""),
            s.get("line", "?"),
            "",                                              # commit_scope — enrichable via git log
            s.get("match", ""),                              # already redacted by scanner
            (s.get("context", "") or "").replace("\n", " ").strip()[:300],
            s.get("engine", ""),
            "ROTATE credential immediately; purge from git history (git-filter-repo / BFG)",
        ])

    # ── 6. Summary sheet ─────────────────────────────────────────────────────
    SUMMARY_HEADER = [
        "scan_type", "severity", "title", "location", "cwe",
        "cve_or_id", "fix_available", "advisory_url",
    ]
    summary_rows: list[list] = []
    for r in sca_rows:
        summary_rows.append([
            r[0], r[2], r[7] or r[4],        # id or pkg
            f"{r[1]} · {r[4]}@{r[5]}",
            r[9], r[8], r[6] != "—", r[13],
        ])
    for r in sast_rows:
        summary_rows.append([
            r[0], r[2], r[4],
            f"{r[1]}:{r[5]}",
            r[6], r[3], "", "",
        ])
    for r in dast_rows:
        summary_rows.append([
            r[0], r[1], r[4],
            r[5], r[8], "", "", "",
        ])
    for r in api_rows:
        summary_rows.append([
            r[0], r[1], r[4],
            r[5], r[8], "", "", "",
        ])
    for r in secrets_rows:
        summary_rows.append([
            r[0], r[1], r[2],
            f"{r[5]}:{r[6]}",
            r[3], "", "", "",
        ])

    # ── Write ZIP with individual sheets ─────────────────────────────────────
    zip_path = path.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        sheets = [
            ("summary.csv",  SUMMARY_HEADER,  summary_rows),
            ("sca.csv",      SCA_HEADER,       sca_rows),
            ("sast.csv",     SAST_HEADER,      sast_rows),
            ("dast.csv",     DAST_HEADER,      dast_rows),
            ("api.csv",      API_HEADER,       api_rows),
            ("secrets.csv",  SECRETS_HEADER,   secrets_rows),
        ]
        for fname, header, rows in sheets:
            buf = io.StringIO()
            _w(buf, header, rows)
            zf.writestr(f"scan_results_{ts}/{fname}", buf.getvalue())

    # Also write a flat unified CSV at the requested path for backwards compat.
    with open(path, "w", newline="", encoding="utf-8") as fh:
        _w(fh, SUMMARY_HEADER, summary_rows)

    return zip_path


# ══════════════════════════════════════════════════════════════════════════════
# ScanStateStore — cumulative last-scan-per-kind persistence
# ──────────────────────────────────────────────────────────────────────────────
# Stores the *raw output* of the most recent run of each scan type so that
# any subsequent report always includes SCA+SAST+DAST+API+Secrets regardless
# of which types were executed in the current session.
#
# On-disk layout (inside <reports_root>/):
#   scan_state.json          — index: timestamps + metadata per kind
#   scan_state_sca.json      — last raw Snyk test output
#   scan_state_code.json     — last raw Snyk Code SARIF output
#   scan_state_dast.json     — last raw DAST findings dict
#   scan_state_api.json      — last raw API scan findings dict
#   scan_state_secrets.json  — last raw secrets-scanner result dict
#
# The "state" for each kind also records:
#   ts       — ISO timestamp of the scan
#   target   — path / URL that was scanned
#   mode     — scan modes active in that run
# ══════════════════════════════════════════════════════════════════════════════

import threading as _threading

_STATE_KINDS = ("sca", "code", "dast", "api", "secrets")
_STATE_INDEX  = "scan_state.json"
_STATE_FILES  = {k: f"scan_state_{k}.json" for k in _STATE_KINDS}


class ScanStateStore:
    """
    Thread-safe, file-backed store of the most-recent raw scan output
    for each scan type (sca, code, dast, api, secrets).

    Usage
    -----
    store = ScanStateStore(reports_root)
    store.save_kind("sca",  raw_data, target=str(target), snyk_version=v)
    store.save_kind("dast", raw_data, target=dast_url)
    ctx = build_cumulative_context(store, target_hint, snyk_version_hint)
    """

    def __init__(self, reports_root: Path):
        self._root  = Path(reports_root)
        self._lock  = _threading.Lock()
        self._root.mkdir(parents=True, exist_ok=True)

    # ── internal ──────────────────────────────────────────────────────────────

    def _index_path(self) -> Path:
        return self._root / _STATE_INDEX

    def _kind_path(self, kind: str) -> Path:
        return self._root / _STATE_FILES[kind]

    def _read_index(self) -> dict:
        p = self._index_path()
        if p.exists():
            try:
                return json.loads(p.read_text("utf-8"))
            except Exception:
                pass
        return {k: None for k in _STATE_KINDS}

    def _write_index(self, idx: dict) -> None:
        self._index_path().write_text(json.dumps(idx, indent=2), "utf-8")

    # ── public API ────────────────────────────────────────────────────────────

    def save_kind(self, kind: str, raw_data: Any, *,
                  target: str = "", snyk_version: str = "",
                  mode: str = "") -> None:
        """
        Persist the raw output of a completed scan stage.
        raw_data is whatever the engine module returned (dict / list / None).
        """
        if kind not in _STATE_KINDS:
            return
        with self._lock:
            idx = self._read_index()
            meta = {
                "ts":            datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                "target":        target,
                "snyk_version":  snyk_version,
                "mode":          mode,
            }
            idx[kind] = meta
            # Write raw payload — wrap None in a sentinel dict
            payload: Any = raw_data if raw_data is not None else {"_empty": True}
            self._kind_path(kind).write_text(
                json.dumps(payload, indent=2, default=str), "utf-8")
            self._write_index(idx)

    def load_kind(self, kind: str) -> tuple[Any, dict]:
        """
        Return (raw_data, meta) for *kind*.
        raw_data is None when nothing has been stored yet or the payload
        was the empty sentinel.
        meta is the index entry dict (may be None if never scanned).
        """
        with self._lock:
            idx = self._read_index()
            meta = idx.get(kind) or {}
            p = self._kind_path(kind)
            if not p.exists():
                return None, meta
            try:
                data = json.loads(p.read_text("utf-8"))
                if isinstance(data, dict) and data.get("_empty"):
                    return None, meta
                return data, meta
            except Exception:
                return None, meta

    def get_index(self) -> dict:
        """Return the full index (kind → meta dict)."""
        with self._lock:
            return self._read_index()

    def clear_kind(self, kind: str) -> None:
        """Erase stored state for one kind."""
        with self._lock:
            idx = self._read_index()
            idx[kind] = None
            self._write_index(idx)
            p = self._kind_path(kind)
            if p.exists():
                p.unlink()

    def clear_all(self) -> None:
        for k in _STATE_KINDS:
            self.clear_kind(k)

    def summary(self) -> dict:
        """
        Returns a human-readable summary dict for display in the UI.
        {kind: {"ts":…, "target":…} or None}
        """
        return self.get_index()


# ── Cumulative context builder ─────────────────────────────────────────────────

def build_cumulative_context(store: "ScanStateStore",
                             target_hint: Any,
                             snyk_version_hint: str = "?",
                             *,
                             current_results: dict | None = None) -> dict:
    """
    Build a report context that merges:
      • whatever was just scanned in this session (current_results, may be partial)
      • the last persisted run of every other kind from the store

    Rules
    -----
    - If a kind is in current_results and its value is not None  →  use current
    - Otherwise load from the store (last persisted)
    - A kind that has never been run at all produces empty data

    Parameters
    ----------
    store            : ScanStateStore instance
    target_hint      : Path or str — used as the report's "target" field
    snyk_version_hint: snyk CLI version from the current session
    current_results  : {"sca": raw|None, "code": raw|None, …}
                       pass {} or None to use only persisted data
    """
    cr = current_results or {}
    idx = store.get_index()

    def _get(kind: str) -> Any:
        if kind in cr and cr[kind] is not None:
            return cr[kind]
        raw, _meta = store.load_kind(kind)
        return raw

    sca_raw     = _get("sca")
    code_raw    = _get("code")
    dast_raw    = _get("dast")
    api_raw     = _get("api")
    secrets_raw = _get("secrets")

    # Resolve best snyk version (current > last stored sca run)
    sv = snyk_version_hint
    if sv in ("?", "", None):
        m = (idx.get("sca") or idx.get("code") or {})
        sv = m.get("snyk_version") or "?"

    # Resolve best target (current > last sca > last code > first stored)
    target = str(target_hint or "")
    if not target or target.endswith("Vulnerable"):
        for k in ("sca", "code", "dast", "api", "secrets"):
            t = (idx.get(k) or {}).get("target", "")
            if t:
                target = t
                break

    ctx = build_context(
        sca_raw, code_raw, target, sv,
        dast_data=dast_raw,
        api_data=api_raw,
        secrets_data=secrets_raw,
    )

    # Annotate context with per-kind timestamps for the report header
    ctx["state_timestamps"] = {
        k: (idx.get(k) or {}).get("ts") for k in _STATE_KINDS
    }
    ctx["state_targets"] = {
        k: (idx.get(k) or {}).get("target") for k in _STATE_KINDS
    }

    return ctx


REPORT_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Vulnerability Report — {{ generated_at }}</title>
<style>
:root{--bg:#fff;--s:#fff;--s2:#f3f4f6;--bd:#e5e7eb;--bd2:#d1d5db;--tx:#111827;
  --mu:#6b7280;--ac:#F5A800;--crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#16a34a;--r:12px}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.55 'Segoe UI',-apple-system,sans-serif}
code,pre,.mono{font-family:ui-monospace,Consolas,monospace}
a{color:#374151;text-decoration:none}a:hover{text-decoration:underline}
.shell{max-width:1480px;margin:0 auto;padding:28px clamp(16px,4vw,48px) 80px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;padding:8px 0 24px}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:38px;height:38px;border-radius:10px;background:var(--ac);color:#fff;display:grid;place-items:center;font-weight:700}
h1{margin:0;font-size:20px}.sub{color:var(--mu);font-size:12px}
.pill{background:var(--s);border:1px solid var(--bd);color:var(--mu);padding:5px 11px;border-radius:999px;font-size:12px;margin-left:6px}
.pill b{color:var(--tx)}
.hero{display:grid;grid-template-columns:1.05fr 1.4fr;gap:20px;margin-bottom:24px}
@media(max-width:980px){.hero{grid-template-columns:1fr}}
.panel{background:var(--s);border:1px solid var(--bd);border-radius:var(--r);padding:20px}
.panel h2{margin:0 0 14px;font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:var(--mu)}
.donut-wrap{display:flex;align-items:center;gap:20px}
.donut{position:relative;width:160px;height:160px;flex:0 0 auto}
.donut svg{transform:rotate(-90deg)}
.donut .center{position:absolute;inset:0;display:grid;place-items:center;text-align:center}
.donut .num{font-size:34px;font-weight:700}.donut .lbl{color:var(--mu);font-size:11px;text-transform:uppercase;letter-spacing:.12em}
.legend{display:grid;gap:9px;flex:1}.legend .item{display:flex;align-items:center;gap:10px}
.sw{width:10px;height:10px;border-radius:3px}.legend .name{flex:1}.legend .val{font-weight:600;color:var(--mu)}
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
@media(max-width:720px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}}
.kpi{border:1px solid var(--bd);border-radius:10px;padding:14px 16px;border-left:3px solid var(--ac)}
.kpi.critical{border-left-color:var(--crit)}.kpi.high{border-left-color:var(--high)}
.kpi.medium{border-left-color:var(--med)}.kpi.low{border-left-color:var(--low)}
.kpi .l{color:var(--mu);font-size:11px;text-transform:uppercase;letter-spacing:.1em}
.kpi .v{font-size:26px;font-weight:700;margin-top:4px}.kpi .s{color:var(--mu);font-size:11px}
.toolbar{position:sticky;top:0;z-index:5;background:rgba(255,255,255,.92);backdrop-filter:blur(8px);
  margin:16px 0;padding:12px 0;border-bottom:1px solid var(--bd);display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.toolbar input{flex:1;min-width:240px;padding:10px 14px;border:1px solid var(--bd);border-radius:10px;font-size:14px;outline:none}
.toolbar input:focus{border-color:var(--ac)}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{cursor:pointer;user-select:none;padding:7px 13px;border-radius:999px;border:1px solid var(--bd);color:var(--mu);font-size:12px;font-weight:600}
.chip .dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--mu);margin-right:5px}
.chip[data-sev=critical] .dot{background:var(--crit)}.chip[data-sev=high] .dot{background:var(--high)}
.chip[data-sev=medium] .dot{background:var(--med)}.chip[data-sev=low] .dot{background:var(--low)}
.chip.active{background:var(--ac);color:#fff;border-color:var(--ac)}.chip.active .dot{background:#fff}
.section-head{display:flex;align-items:baseline;gap:10px;margin:26px 0 12px}
.section-head h3{margin:0;font-size:18px}
.count{background:var(--s);border:1px solid var(--bd);color:var(--mu);font-size:12px;padding:2px 9px;border-radius:999px}
.hint{color:var(--mu);font-size:12px;margin-left:auto}
details.group{background:var(--s);border:1px solid var(--bd);border-radius:var(--r);margin-bottom:12px;overflow:hidden}
details.group>summary{cursor:pointer;padding:13px 16px;display:flex;align-items:center;gap:12px;list-style:none}
details.group>summary::-webkit-details-marker{display:none}
details.group[open]>summary{border-bottom:1px solid var(--bd)}
.gt{font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.gm{display:flex;gap:6px}
.mini{font-size:10px;padding:2px 7px;border-radius:999px;font-weight:700;text-transform:uppercase}
.mini.critical,.sev.critical{background:rgba(220,38,38,.1);color:var(--crit)}
.mini.high,.sev.high{background:rgba(234,88,12,.1);color:var(--high)}
.mini.medium,.sev.medium{background:rgba(217,119,6,.1);color:var(--med)}
.mini.low,.sev.low{background:rgba(22,163,74,.1);color:var(--low)}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--mu);font-size:11px;text-transform:uppercase;letter-spacing:.08em;padding:10px 14px;border-bottom:1px solid var(--bd)}
td{padding:11px 14px;vertical-align:top;border-bottom:1px solid var(--bd)}
tr:last-child td{border-bottom:0}tr:hover td{background:var(--s2)}
td code{background:var(--s2);border:1px solid var(--bd);padding:1px 6px;border-radius:6px;font-size:12px}
.desc{color:var(--mu);font-size:12px;margin-top:4px;max-width:720px}
.sev{display:inline-block;padding:3px 10px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase}
pre.snippet{background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:10px;overflow:auto;font-size:12px;max-height:200px;margin:8px 0 0}
.empty{text-align:center;padding:34px;color:var(--mu);border:1px dashed var(--bd2);border-radius:var(--r)}
footer{text-align:center;color:var(--mu);font-size:12px;padding:30px 0 0}
.hide{display:none!important}
.state-bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;
  background:#fffbef;border:1px solid #f0e0a0;border-radius:10px;
  padding:9px 16px;margin-bottom:20px;font-size:12px}
.state-label{font-weight:700;color:#7a5c00;margin-right:4px}
.state-pill{display:inline-flex;align-items:center;gap:5px;
  padding:4px 11px;border-radius:999px;border:1px solid #e5e7eb;
  background:#fff;font-size:11px;color:var(--mu)}
.state-pill.state-ok{background:#f0fdf4;border-color:#86efac;color:#166534}
.state-pill.state-ok b{color:#15803d;font-weight:700}
.state-pill.state-none{opacity:.55}
</style></head><body><div class="shell">
{% set c=counts.critical or 0 %}{% set h=counts.high or 0 %}
{% set m=counts.medium or 0 %}{% set l=counts.low or 0 %}
{% set sum=(c+h+m+l) if (c+h+m+l)>0 else 1 %}{% set circ=99.95 %}
<header class="topbar">
  <div class="brand"><div class="logo">VS</div>
    <div><h1>Vulnerability Report</h1><div class="sub">SCA · SAST · DAST · API · Secrets — Cumulative view</div></div></div>
  <div>
    <span class="pill">Generated <b>{{ generated_at }}</b></span>
    <span class="pill">Snyk <b>{{ snyk_version or '?' }}</b></span>
    {% if scan_mode %}<span class="pill">Session <b>{{ scan_mode|upper }}</b></span>{% endif %}
  </div>
</header>
{% if state_timestamps %}
<div class="state-bar">
  <span class="state-label">📊 Cumulative scan sources:</span>
  {% set ts=state_timestamps %}{% set tg=state_targets %}
  {% set labels=[('sca','SCA','🔍'),('code','SAST','🧬'),('dast','DAST','🌐'),('api','API','🔌'),('secrets','Secrets','🔑')] %}
  {% for kind,name,icon in labels %}
  <span class="state-pill {% if ts[kind] %}state-ok{% else %}state-none{% endif %}">
    {{ icon }} {{ name }}
    {% if ts[kind] %}<b>{{ ts[kind][:16] }}</b>{% else %}<em>never</em>{% endif %}
  </span>
  {% endfor %}
</div>
{% endif %}
<section class="hero">
  <div class="panel"><h2>Severity distribution</h2><div class="donut-wrap">
    <div class="donut"><svg viewBox="0 0 42 42" width="160" height="160">
      <circle cx="21" cy="21" r="15.915" fill="none" stroke="#e5e7eb" stroke-width="3.6"/>
      {% set o1=0 %}{% set l1=c*circ/sum %}{% set o2=l1 %}{% set l2=h*circ/sum %}
      {% set o3=l1+l2 %}{% set l3=m*circ/sum %}{% set o4=l1+l2+l3 %}{% set l4=l*circ/sum %}
      {% for col,ln,of in [('#dc2626',l1,o1),('#ea580c',l2,o2),('#d97706',l3,o3),('#16a34a',l4,o4)] %}
      <circle cx="21" cy="21" r="15.915" fill="none" stroke="{{ col }}" stroke-width="3.8"
        stroke-dasharray="{{ '%.2f'|format(ln) }} {{ '%.2f'|format(circ-ln) }}"
        stroke-dashoffset="{{ '%.2f'|format(-of) }}"/>{% endfor %}
    </svg><div class="center"><div><div class="num">{{ total or 0 }}</div>
      <div class="lbl">Total issues</div></div></div></div>
    <div class="legend">
      {% for nm,cl,vv in [('Critical','#dc2626',c),('High','#ea580c',h),('Medium','#d97706',m),('Low','#16a34a',l)] %}
      <div class="item"><span class="sw" style="background:{{ cl }}"></span>
        <span class="name">{{ nm }}</span><span class="val">{{ vv }}</span></div>{% endfor %}
    </div></div></div>
  <div class="panel"><h2>Breakdown</h2><div class="kpis">
    {% for cls,lbl,vv,sub in [('critical','Critical',c,'Immediate attention'),('high','High',h,'Fix soon'),('medium','Medium',m,'Plan a fix'),('low','Low',l,'Track')] %}
    <div class="kpi {{ cls }}"><div class="l">{{ lbl }}</div><div class="v">{{ vv }}</div><div class="s">{{ sub }}</div></div>{% endfor %}
    <div class="kpi"><div class="l">SCA</div><div class="v">{{ sca_total }}</div><div class="s">Dependencies</div></div>
    <div class="kpi"><div class="l">SAST</div><div class="v">{{ code_total }}</div><div class="s">Source code</div></div>
    <div class="kpi"><div class="l">DAST</div><div class="v">{{ dast_total or 0 }}</div><div class="s">Dynamic scan</div></div>
    <div class="kpi"><div class="l">API</div><div class="v">{{ api_total or 0 }}</div><div class="s">Endpoint scan</div></div>
    <div class="kpi critical"><div class="l">🔑 Secrets</div><div class="v">{{ secrets_total or 0 }}</div><div class="s">Hard-coded creds</div></div>
  </div></div>
</section>
<div class="toolbar">
  <input id="search" type="search" placeholder="Filter by package, file, rule, CVE/CWE…" autocomplete="off"/>
  <div class="chips" id="chips">
    <span class="chip active" data-sev="all"><span class="dot"></span>All <b>{{ total or 0 }}</b></span>
    {% for s,v in [('critical',c),('high',h),('medium',m),('low',l)] %}
    <span class="chip" data-sev="{{ s }}"><span class="dot"></span>{{ s|capitalize }} <b>{{ v }}</b></span>{% endfor %}
  </div>
</div>
{% macro mini(items) %}{% for s,a in [('critical','C'),('high','H'),('medium','M'),('low','L')] %}
{% set n=items|selectattr('severity','equalto',s)|list|length %}
{% if n %}<span class="mini {{ s }}">{{ n }} {{ a }}</span>{% endif %}{% endfor %}{% endmacro %}

<div class="section-head"><h3>Open-source (SCA)</h3><span class="count">{{ sca_total }}</span>
  <span class="hint">{{ projects|length }} project{{ '' if projects|length==1 else 's' }}{% if state_timestamps and state_timestamps.sca %}  ·  last scan {{ state_timestamps.sca[:16] }}{% endif %}</span></div>
{% if not projects %}<div class="empty">No manifests detected or no vulnerabilities found.</div>{% endif %}
{% for p in projects %}<details class="group" {% if p.issues %}open{% endif %}>
  <summary><span class="gt mono">{{ p.project }}</span><span class="gm">{{ mini(p.issues) }}</span></summary>
  {% if p.error %}<div style="padding:16px;color:var(--mu)">Error: {{ p.error }}</div>
  {% elif p.issues %}<div class="table-wrap"><table>
    <thead><tr><th>Severity</th><th>Vulnerable Package</th><th>Installed ver.</th><th>Fixed in</th><th>Title / Advisory</th><th>CVE</th><th>CWE</th><th>Dependency path</th><th>Transitive?</th></tr></thead><tbody>
    {% for i in p.issues %}
      {% set pkg_name = i.package.split('@')[0] if '@' in i.package else i.package %}
      {% set pkg_ver  = i.package.split('@')[1] if '@' in i.package else '' %}
      {% set is_trans = i.path not in ('(direct)', '') %}
    <tr class="row" data-sev="{{ i.severity }}"
      data-text="{{ (i.package~' '~i.title~' '~i.cve~' '~i.cwe~' '~i.path)|lower }}">
      <td><span class="sev {{ i.severity }}">{{ i.severity }}</span></td>
      <td><code>{{ pkg_name }}</code></td>
      <td><code>{{ pkg_ver or '—' }}</code></td>
      <td>{% if i.fixedIn and i.fixedIn != '—' %}<span style="color:var(--low);font-weight:600">{{ i.fixedIn }}</span>{% else %}<span style="color:var(--mu)">—</span>{% endif %}</td>
      <td>{% if i.url %}<a href="{{ i.url }}" target="_blank">{{ i.title }}</a>{% else %}{{ i.title }}{% endif %}
        {% if i.description %}<div class="desc">{{ i.description[:300] }}</div>{% endif %}</td>
      <td>{% if i.cve %}<code style="color:var(--crit)">{{ i.cve }}</code>{% else %}<span style="color:var(--mu)">—</span>{% endif %}</td>
      <td><code>{{ i.cwe or '—' }}</code></td>
      <td class="mono" style="font-size:11px">{{ i.path or '(direct)' }}</td>
      <td style="text-align:center">{% if is_trans %}<span class="mini medium">indirect</span>{% else %}<span class="mini low">direct</span>{% endif %}</td>
    </tr>{% endfor %}
    </tbody></table></div>
  {% else %}<div style="padding:16px;color:var(--mu)">No vulnerabilities found.</div>{% endif %}
</details>{% endfor %}

<div class="section-head"><h3>Static code (SAST)</h3><span class="count">{{ code_total }}</span>
  <span class="hint">{{ files|length }} file{{ '' if files|length==1 else 's' }}{% if state_timestamps and state_timestamps.code %}  ·  last scan {{ state_timestamps.code[:16] }}{% endif %}</span></div>
{% if not files %}<div class="empty">No SAST issues found.</div>{% endif %}
{% for f in files %}<details class="group" open>
  <summary><span class="gt mono">{{ f.file }}</span><span class="gm">{{ mini(f.issues) }}</span></summary>
  <div class="table-wrap"><table>
    <thead><tr><th>Severity</th><th>Rule ID</th><th>Rule name</th><th>Line</th><th>CWE</th><th>OWASP category</th><th>Message</th><th>Code snippet</th></tr></thead><tbody>
    {% set _SAST_OWASP = {'CWE-79':'A03 Injection','CWE-89':'A03 Injection','CWE-94':'A03 Injection','CWE-78':'A03 Injection','CWE-918':'A10 SSRF','CWE-611':'A05 Misconfiguration','CWE-22':'A01 Broken Access Control','CWE-352':'A01 Broken Access Control','CWE-862':'A01 Broken Access Control','CWE-502':'A08 Insecure Deserialization','CWE-327':'A02 Crypto Failures','CWE-326':'A02 Crypto Failures','CWE-798':'A07 Auth Failures','CWE-259':'A07 Auth Failures','CWE-287':'A07 Auth Failures','CWE-532':'A09 Logging Failures'} %}
    {% for i in f.issues %}
      {% set cwe_key = i.cwe.split(',')[0].strip().upper() %}
      {% set owasp_cat = _SAST_OWASP.get(cwe_key, '') %}
    <tr class="row" data-sev="{{ i.severity }}"
      data-text="{{ (i.rule~' '~i.title~' '~i.message~' '~i.cwe)|lower }}">
      <td><span class="sev {{ i.severity }}">{{ i.severity }}</span></td>
      <td><code>{{ i.rule }}</code></td>
      <td style="font-weight:600">{{ i.title or i.rule }}</td>
      <td style="text-align:center"><code>{{ i.line }}</code></td>
      <td><code>{{ i.cwe or '—' }}</code></td>
      <td style="font-size:11px;color:var(--mu)">{{ owasp_cat or '—' }}</td>
      <td>{{ i.message }}</td>
      <td>{% if i.snippet %}<pre class="snippet">{{ i.snippet[:500] }}</pre>{% else %}<span style="color:var(--mu)">—</span>{% endif %}</td>
    </tr>{% endfor %}
    </tbody></table></div>
</details>{% endfor %}

{% if dast.findings or dast.pages_visited %}
<div class="section-head"><h3>Dynamic (DAST) — {{ dast.target }}</h3>
  <span class="count">{{ dast_total }}</span>
  <span class="hint">{{ dast.pages_visited }} pages · {{ dast.profile }}{% if state_timestamps and state_timestamps.dast %}  ·  last scan {{ state_timestamps.dast[:16] }}{% endif %}</span></div>
{% if not dast.findings %}<div class="empty">No DAST issues found.</div>{% endif %}
{% if dast.findings %}<details class="group" open>
  <summary><span class="gt">DAST findings</span><span class="gm">{{ mini(dast.findings) }}</span></summary>
  {% set _DAST_SOL = {'auth':'Enforce strong authentication; implement MFA.','injection':'Use parameterised queries / strict input validation.','csrf':'Add CSRF tokens; validate Origin/Referer headers.','headers':'Configure security headers (CSP, HSTS, X-Frame-Options).','ssl':'Enforce TLS 1.2+; disable weak ciphers.','redirect':'Whitelist redirect targets; reject arbitrary URLs.','xss':'Encode output; implement strict Content-Security-Policy.','sqli':'Use parameterised queries; never concatenate user input.','cors':'Restrict CORS to trusted origins; avoid wildcard (*).','info':'Remove verbose errors; suppress server version headers.'} %}
  {% set _DAST_OWASP = {'auth':'API2 Broken Auth','injection':'API8 Injection','csrf':'API6 Mass Assignment','headers':'API7 Misconfiguration','ssl':'API7 Misconfiguration','redirect':'API3 Excessive Data Exposure','xss':'API8 Injection','sqli':'API8 Injection','cors':'API7 Misconfiguration','info':'API9 Improper Assets'} %}
  <div class="table-wrap"><table>
    <thead><tr><th>Severity</th><th>OWASP API</th><th>Category</th><th>Title</th><th>URL</th><th>Method</th><th>Parameter</th><th>CWE</th><th>Evidence</th><th>Recommended fix</th></tr></thead><tbody>
    {% for d in dast.findings %}
      {% set cat_key = (d.category or '')|lower %}
    <tr class="row" data-sev="{{ d.severity }}"
      data-text="{{ (d.title~' '~d.url~' '~(d.cwe or '')~' '~(d.category or ''))|lower }}">
      <td><span class="sev {{ d.severity }}">{{ d.severity }}</span></td>
      <td style="font-size:11px;white-space:nowrap">{{ _DAST_OWASP.get(cat_key, '—') }}</td>
      <td>{{ d.category or '—' }}</td>
      <td style="font-weight:600">{{ d.title }}</td>
      <td class="mono"><a href="{{ d.url }}" target="_blank" style="font-size:11px">{{ d.url[:70] }}</a></td>
      <td><code>{{ d.method or '—' }}</code></td>
      <td><code>{{ d.param or '—' }}</code></td>
      <td><code>{{ d.cwe or '—' }}</code></td>
      <td class="mono" style="font-size:11px">{{ (d.evidence or '')[:150] }}</td>
      <td style="font-size:11px;color:var(--mu)">{{ _DAST_SOL.get(cat_key, '—') }}</td>
    </tr>{% endfor %}
    </tbody></table></div>
</details>{% endif %}{% endif %}

{% if api.findings or api.endpoints_tested %}
<div class="section-head"><h3>API Security</h3>
  <span class="count">{{ api_total }}</span>
  <span class="hint">{{ api.endpoints_tested }}/{{ api.endpoints_total }} endpoints · {{ api.profile }}{% if state_timestamps and state_timestamps.api %}  ·  last scan {{ state_timestamps.api[:16] }}{% endif %}</span></div>
{% if not api.findings %}<div class="empty">No API security issues found.</div>{% endif %}
{% if api.findings %}<details class="group" open>
  <summary><span class="gt">API findings</span><span class="gm">{{ mini(api.findings) }}</span></summary>
  {% set _API_SOL = {'auth':'Enforce strong authentication; implement MFA.','injection':'Use parameterised queries / strict input validation.','csrf':'Add CSRF tokens; validate Origin/Referer headers.','headers':'Configure security headers (CSP, HSTS, X-Frame-Options).','ssl':'Enforce TLS 1.2+; disable weak ciphers.','redirect':'Whitelist redirect targets; reject arbitrary URLs.','xss':'Encode output; implement strict Content-Security-Policy.','sqli':'Use parameterised queries; never concatenate user input.','cors':'Restrict CORS to trusted origins; avoid wildcard (*).','info':'Remove verbose errors; suppress server version headers.'} %}
  {% set _API_OWASP = {'auth':'API2 Broken Auth','injection':'API8 Injection','csrf':'API6 Mass Assignment','headers':'API7 Misconfiguration','ssl':'API7 Misconfiguration','redirect':'API3 Excessive Data Exposure','xss':'API8 Injection','sqli':'API8 Injection','cors':'API7 Misconfiguration','info':'API9 Improper Assets','no-auth':'API1 Broken Object Level Auth','bola':'API1 Broken Object Level Auth','rate-limit':'API4 Unrestricted Resource Consumption'} %}
  <div class="table-wrap"><table>
    <thead><tr><th>Severity</th><th>OWASP API Top-10</th><th>Category</th><th>Title</th><th>Endpoint URL</th><th>HTTP Method</th><th>Parameter</th><th>CWE</th><th>Auth Required?</th><th>Evidence</th><th>Recommended fix</th></tr></thead><tbody>
    {% for d in api.findings %}
      {% set cat_key = (d.category or '')|lower %}
    <tr class="row" data-sev="{{ d.severity }}"
      data-text="{{ (d.title~' '~d.url~' '~(d.cwe or '')~' '~(d.category or ''))|lower }}">
      <td><span class="sev {{ d.severity }}">{{ d.severity }}</span></td>
      <td style="font-size:11px;white-space:nowrap">{{ _API_OWASP.get(cat_key, '—') }}</td>
      <td>{{ d.category or '—' }}</td>
      <td style="font-weight:600">{{ d.title }}</td>
      <td class="mono"><a href="{{ d.url }}" target="_blank" style="font-size:11px">{{ d.url[:70] }}</a></td>
      <td><code>{{ d.method or '—' }}</code></td>
      <td><code>{{ d.param or '—' }}</code></td>
      <td><code>{{ d.cwe or '—' }}</code></td>
      <td style="text-align:center">{% if d.auth_required is not none %}{% if d.auth_required %}<span class="mini low">Yes</span>{% else %}<span class="mini high">No</span>{% endif %}{% else %}<span style="color:var(--mu)">—</span>{% endif %}</td>
      <td class="mono" style="font-size:11px">{{ (d.evidence or '')[:150] }}</td>
      <td style="font-size:11px;color:var(--mu)">{{ _API_SOL.get(cat_key, '—') }}</td>
    </tr>{% endfor %}
    </tbody></table></div>
</details>{% endif %}{% endif %}

{% if secrets.findings or secrets.scanned_files %}
<div class="section-head"><h3>🔑 Secrets / Hard-coded Credentials</h3>
  <span class="count">{{ secrets_total }}</span>
  <span class="hint">{{ secrets.scanned_files }} files scanned · engine: {{ secrets.engine or 'built-in' }}{% if state_timestamps and state_timestamps.secrets %}  ·  last scan {{ state_timestamps.secrets[:16] }}{% endif %}</span></div>
<p style="font-size:12px;color:var(--mu);margin:0 0 12px">
  Findings follow <b>CWE-798</b> (Use of Hard-coded Credentials) and
  <b>CWE-259</b> (Use of Hard-coded Password). All matched values are
  redacted. Treat any flagged credential as compromised: <b>rotate it</b>
  and purge it from version-control history (git-filter-repo / BFG).
</p>
{% if not secrets.findings %}<div class="empty">No hard-coded secrets detected.</div>{% endif %}
{% if secrets.findings %}<details class="group" open>
  <summary><span class="gt">Secret findings</span><span class="gm">{{ mini(secrets.findings) }}</span></summary>
  {% set _SEC_CWE = {'private key block':'CWE-321','aws access key id':'CWE-798','aws secret access key':'CWE-798','aws session token':'CWE-798','generic hard-coded secret':'CWE-259','credentials embedded in url':'CWE-522','json web token':'CWE-522'} %}
  <div class="table-wrap"><table>
    <thead>
      <tr>
        <th>Severity</th><th>Secret type</th><th>CWE</th><th>OWASP Top 10</th>
        <th>File path</th><th>Line</th>
        <th>Secret (redacted)</th><th>Context snippet</th>
        <th>Engine</th><th>Remediation action</th>
      </tr>
    </thead><tbody>
    {% for s in secrets.findings %}
      {% set stype_key = (s.secret_type or s.rule or '')|lower %}
      {% set eff_cwe   = s.cwe if s.cwe else _SEC_CWE.get(stype_key, 'CWE-798') %}
    <tr class="row" data-sev="{{ s.severity }}"
      data-text="{{ (s.secret_type~' '~s.file~' '~s.rule~' '~s.cwe)|lower }}">
      <td><span class="sev {{ s.severity }}">{{ s.severity }}</span></td>
      <td style="font-weight:600;white-space:nowrap">{{ s.secret_type or s.rule }}</td>
      <td><code>{{ eff_cwe }}</code></td>
      <td style="font-size:11px;color:var(--mu);white-space:nowrap">A07 Auth Failures</td>
      <td class="mono"><code>{{ s.file }}</code></td>
      <td style="text-align:center"><code>{{ s.line }}</code></td>
      <td><code style="color:var(--crit)">{{ s.match }}</code>
        {% if s.context %}<div class="desc mono">{{ s.context }}</div>{% endif %}</td>
      <td style="font-size:11px">{% if s.context %}<pre class="snippet" style="max-height:80px">{{ s.context[:300] }}</pre>{% else %}—{% endif %}</td>
      <td style="font-size:11px">{{ s.engine or 'built-in' }}</td>
      <td style="font-size:11px;color:var(--crit);font-weight:600">🔁 ROTATE immediately &amp; purge from git history</td>
    </tr>{% endfor %}
    </tbody></table></div>
</details>{% endif %}{% endif %}

<footer>Generated by Vulnerability Scanner · Snyk {{ snyk_version or '?' }} · {{ generated_at }}</footer>
</div>
<script>
(function(){
  var rows=document.querySelectorAll('.row'),chips=document.querySelectorAll('.chip'),search=document.getElementById('search');
  var curSev='all',curQ='';
  function filter(){rows.forEach(function(r){var sev=r.dataset.sev,txt=r.dataset.text||'';
    var ok=(curSev==='all'||sev===curSev)&&(!curQ||txt.includes(curQ));r.classList.toggle('hide',!ok);});}
  chips.forEach(function(c){c.onclick=function(){chips.forEach(function(x){x.classList.remove('active');});
    c.classList.add('active');curSev=c.dataset.sev;filter();};});
  if(search){search.oninput=function(){curQ=search.value.toLowerCase();filter();};
    document.addEventListener('keydown',function(e){if(e.key==='/'&&document.activeElement!==search){e.preventDefault();search.focus();}});}
})();
</script>
</body></html>
"""

def render_html(ctx: dict, out_dir: Path) -> Path:
    html = Template(REPORT_TEMPLATE).render(**ctx)
    path = out_dir / "report.html"
    path.write_text(html, encoding="utf-8")
    return path


# ══════════════════════════════════════════════════════════════════════════════
# Remediation history
# ──────────────────────────────────────────────────────────────────────────────
# Persists a per-reports-folder log of every scan plus the deltas between
# consecutive scans (which findings were remediated, which are new, which
# persist), and any manual remediation actions. Gives the reporting system a
# longitudinal "histórico de remediaciones" instead of isolated point-in-time
# reports.
# ══════════════════════════════════════════════════════════════════════════════
import hashlib

HISTORY_FILENAME = "remediation_history.json"
_HISTORY_VERSION = 1


def _sig(*parts: Any) -> str:
    """Stable short signature for a finding (survives across scans)."""
    raw = "|".join("" if p is None else str(p) for p in parts).lower()
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:16]


def collect_signatures(ctx: dict) -> dict[str, dict]:
    """Map every finding in a built context to a stable signature → summary."""
    sigs: dict[str, dict] = {}

    def _base(name: Path | str) -> str:
        try: return Path(str(name)).name or str(name)
        except Exception: return str(name)

    for p in ctx.get("projects", []):
        proj = _base(p.get("project", ""))
        for i in p.get("issues", []):
            s = _sig("sca", proj, i.get("package"), i.get("id") or i.get("title"))
            sigs[s] = {"kind": "sca", "severity": i.get("severity", "low"),
                       "title": i.get("title", ""), "where": f"{proj} · {i.get('package','')}"}
    for f in ctx.get("files", []):
        fl = _base(f.get("file", ""))
        for i in f.get("issues", []):
            s = _sig("sast", fl, i.get("rule"), i.get("title") or i.get("message"))
            sigs[s] = {"kind": "sast", "severity": i.get("severity", "low"),
                       "title": i.get("title") or i.get("message", ""),
                       "where": f"{fl}:{i.get('line','?')}"}
    for kind in ("dast", "api"):
        for d in (ctx.get(kind, {}) or {}).get("findings", []):
            url = d.get("url", "")
            try:
                from urllib.parse import urlparse
                path = urlparse(url).path or url
            except Exception:
                path = url
            s = _sig(kind, d.get("category"), path, d.get("title"))
            sigs[s] = {"kind": kind, "severity": d.get("severity", "low"),
                       "title": d.get("title", ""), "where": path}
    for sec in (ctx.get("secrets", {}) or {}).get("findings", []):
        s = _sig("secrets", sec.get("rule"), sec.get("file"), sec.get("line"))
        sigs[s] = {"kind": "secrets", "severity": sec.get("severity", "high"),
                   "title": sec.get("secret_type") or sec.get("rule", ""),
                   "where": f"{sec.get('file', '')}:{sec.get('line', '?')}"}
    return sigs


def load_history(reports_root) -> dict:
    p = Path(reports_root) / HISTORY_FILENAME
    if not p.exists():
        return {"version": _HISTORY_VERSION, "scans": [], "actions": []}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        data.setdefault("scans", []); data.setdefault("actions", [])
        return data
    except Exception:
        return {"version": _HISTORY_VERSION, "scans": [], "actions": []}


def save_history(reports_root, data: dict) -> Path:
    p = Path(reports_root) / HISTORY_FILENAME
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return p


def update_history_after_scan(reports_root, ctx: dict, meta: dict, *,
                              actor: str | None = None,
                              report_dir=None) -> dict:
    """Append a scan to the history and compute the remediation delta vs the
    previous scan with a matching scan mode. Returns the new scan record."""
    history = load_history(reports_root)
    sigs = collect_signatures(ctx)
    cur = set(sigs.keys())
    mode = meta.get("mode") or ctx.get("scan_mode") or "?"

    prev = None
    for rec in reversed(history["scans"]):
        if rec.get("mode") == mode:
            prev = rec; break
    if prev is None and history["scans"]:
        prev = history["scans"][-1]

    prev_sigs = set((prev or {}).get("signatures", []))
    remediated = sorted(prev_sigs - cur) if prev else []
    introduced = sorted(cur - prev_sigs) if prev else sorted(cur)
    persisting = sorted(cur & prev_sigs) if prev else []

    record = {
        "ts": ctx.get("generated_at") or _ts(),
        "mode": mode,
        "target": meta.get("target") or ctx.get("target", ""),
        "total": ctx.get("total", 0),
        "counts": dict(ctx.get("counts", {})),
        "actor": actor or "",
        "report_dir": str(report_dir) if report_dir else "",
        "signatures": sorted(cur),
        "remediated_count": len(remediated),
        "introduced_count": len(introduced),
        "persisting_count": len(persisting),
        "remediated": [
            {"sig": s, **(prev.get("sig_index", {}).get(s, {}))} for s in remediated
        ] if prev else [],
        "sig_index": {s: {"title": v["title"], "severity": v["severity"],
                          "where": v["where"], "kind": v["kind"]}
                      for s, v in sigs.items()},
    }
    history["scans"].append(record)

    # Auto-log a remediation action for each disappeared finding.
    for item in record["remediated"]:
        history["actions"].append({
            "ts": record["ts"], "actor": actor or "auto",
            "status": "remediated", "source": "auto",
            "sig": item.get("sig", ""),
            "title": item.get("title", ""),
            "severity": item.get("severity", ""),
            "where": item.get("where", ""),
            "note": f"No longer detected in {mode.upper()} scan",
        })
    save_history(reports_root, history)
    return record


def add_remediation_action(reports_root, *, title: str, status: str = "remediated",
                           note: str = "", actor: str = "", severity: str = "",
                           where: str = "", sig: str = "") -> dict:
    """Record a manual remediation action."""
    history = load_history(reports_root)
    entry = {"ts": _ts_human(), "actor": actor or "", "status": status,
             "source": "manual", "sig": sig, "title": title,
             "severity": severity, "where": where, "note": note}
    history["actions"].append(entry)
    save_history(reports_root, history)
    return entry


def _ts_human() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


_HISTORY_TEMPLATE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Remediation History — {{ now }}</title><style>
:root{--bg:#fff;--s:#fff;--s2:#f3f4f6;--bd:#e5e7eb;--tx:#111827;--mu:#6b7280;
--ac:#F5A800;--crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#16a34a;--ok:#16a34a;--r:12px}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);
font:14px/1.55 'Segoe UI',-apple-system,Roboto,sans-serif}
.shell{max-width:1280px;margin:0 auto;padding:30px clamp(16px,4vw,48px) 80px}
.top{display:flex;align-items:center;gap:14px;margin-bottom:22px;flex-wrap:wrap}
.logo{width:42px;height:42px;border-radius:11px;background:var(--ac);color:#fff;
display:grid;place-items:center;font-weight:800;font-size:20px}
h1{margin:0;font-size:22px}.sub{color:var(--mu);font-size:12px}
.pill{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}
.tag{background:var(--s);border:1px solid var(--bd);border-radius:999px;padding:6px 12px;font-size:12px;color:var(--mu)}.tag b{color:var(--tx)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:6px 0 24px}
@media(max-width:760px){.kpis{grid-template-columns:repeat(2,1fr)}}
.kpi{border:1px solid var(--bd);border-radius:12px;padding:16px;border-left:4px solid var(--ac)}
.kpi.good{border-left-color:var(--ok)}.kpi.bad{border-left-color:var(--crit)}
.kpi .l{color:var(--mu);font-size:11px;text-transform:uppercase;letter-spacing:.1em}
.kpi .v{font-size:30px;font-weight:800;margin-top:6px}
.panel{background:var(--s);border:1px solid var(--bd);border-radius:var(--r);padding:20px;margin-bottom:24px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:var(--mu);margin:0 0 14px}
.chart{width:100%;height:240px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--mu);font-size:11px;text-transform:uppercase;letter-spacing:.07em;padding:10px 12px;border-bottom:1px solid var(--bd)}
td{padding:10px 12px;border-bottom:1px solid var(--bd);vertical-align:top}
tr:last-child td{border-bottom:0}
code{font-family:ui-monospace,Menlo,Consolas,monospace;background:var(--s2);border:1px solid var(--bd);border-radius:6px;padding:1px 6px;font-size:12px}
.sev{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase}
.sev.critical{background:#dc262618;color:var(--crit)}.sev.high{background:#ea580c18;color:var(--high)}
.sev.medium{background:#d9770618;color:var(--med)}.sev.low{background:#16a34a18;color:var(--low)}
.delta-pos{color:var(--ok);font-weight:700}.delta-neg{color:var(--crit);font-weight:700}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700}
.badge.remediated{background:#16a34a18;color:var(--ok)}.badge.manual{background:#F5A80022;color:#9a6b00}
.badge.regression{background:#dc262618;color:var(--crit)}
.empty{text-align:center;padding:40px;color:var(--mu);border:1px dashed var(--bd);border-radius:var(--r)}
footer{text-align:center;color:var(--mu);font-size:12px;padding:30px 0 0}
</style></head><body><div class="shell">
<div class="top"><div class="logo">🩹</div>
<div><h1>Remediation History</h1><div class="sub">Longitudinal view of findings fixed over time</div></div>
<div class="pill"><span class="tag">Scans <b>{{ scans|length }}</b></span>
<span class="tag">Actions <b>{{ actions|length }}</b></span>
<span class="tag">Generated <b>{{ now }}</b></span></div></div>

<div class="kpis">
<div class="kpi good"><div class="l">Total remediated</div><div class="v">{{ total_remediated }}</div></div>
<div class="kpi bad"><div class="l">Total introduced</div><div class="v">{{ total_introduced }}</div></div>
<div class="kpi"><div class="l">Latest open issues</div><div class="v">{{ latest_total }}</div></div>
<div class="kpi"><div class="l">Manual actions</div><div class="v">{{ manual_actions }}</div></div>
</div>

{% if points|length > 1 %}
<div class="panel"><h2>Open issues over time</h2>
<svg class="chart" viewBox="0 0 {{ vw }} {{ vh }}" preserveAspectRatio="none">
  <line x1="40" y1="{{ vh-26 }}" x2="{{ vw-10 }}" y2="{{ vh-26 }}" stroke="#e5e7eb"/>
  <polyline fill="none" stroke="#F5A800" stroke-width="2.5"
    points="{{ polyline }}"/>
  {% for px,py,val in dots %}
  <circle cx="{{ px }}" cy="{{ py }}" r="3.5" fill="#F5A800"/>
  <text x="{{ px }}" y="{{ py-9 }}" font-size="11" fill="#6b7280" text-anchor="middle">{{ val }}</text>
  {% endfor %}
</svg></div>
{% endif %}

<div class="panel"><h2>Scan timeline</h2>
{% if not scans %}<div class="empty">No scans recorded yet.</div>{% else %}
<table><thead><tr><th>When</th><th>Mode</th><th>Open</th><th>Critical</th><th>High</th>
<th>Remediated</th><th>New</th><th>By</th></tr></thead><tbody>
{% for s in scans|reverse %}
<tr><td>{{ s.ts }}</td><td><code>{{ s.mode|upper }}</code></td>
<td><b>{{ s.total }}</b></td>
<td>{{ s.counts.critical or 0 }}</td><td>{{ s.counts.high or 0 }}</td>
<td>{% if s.remediated_count %}<span class="delta-pos">−{{ s.remediated_count }}</span>{% else %}0{% endif %}</td>
<td>{% if s.introduced_count %}<span class="delta-neg">+{{ s.introduced_count }}</span>{% else %}0{% endif %}</td>
<td>{{ s.actor or '—' }}</td></tr>
{% endfor %}
</tbody></table>{% endif %}</div>

<div class="panel"><h2>Remediation log</h2>
{% if not actions %}<div class="empty">No remediation actions recorded yet.</div>{% else %}
<table><thead><tr><th>When</th><th>Status</th><th>Severity</th><th>Finding</th><th>Where</th><th>By</th><th>Note</th></tr></thead><tbody>
{% for a in actions|reverse %}
<tr><td>{{ a.ts }}</td>
<td><span class="badge {{ 'manual' if a.source=='manual' else 'remediated' }}">{{ a.status }}</span></td>
<td>{% if a.severity %}<span class="sev {{ a.severity }}">{{ a.severity }}</span>{% else %}—{% endif %}</td>
<td>{{ a.title or '—' }}</td><td class="mono"><code>{{ a.where or '—' }}</code></td>
<td>{{ a.actor or '—' }}</td><td>{{ a.note or '' }}</td></tr>
{% endfor %}
</tbody></table>{% endif %}</div>

<footer>Vulnerability Scanner · Remediation history · {{ now }}</footer>
</div></body></html>"""


def render_remediation_history(reports_root, out_path=None) -> Path:
    history = load_history(reports_root)
    scans = history.get("scans", [])
    actions = history.get("actions", [])

    total_remediated = sum(s.get("remediated_count", 0) for s in scans)
    total_introduced = sum(s.get("introduced_count", 0) for s in scans)
    latest_total = scans[-1].get("total", 0) if scans else 0
    manual_actions = sum(1 for a in actions if a.get("source") == "manual")

    # Build a simple SVG line chart of open-issue totals over time.
    vw, vh = 900, 240
    pts = [s.get("total", 0) for s in scans]
    points = ""; dots = []
    if len(pts) > 1:
        lo, hi = min(pts), max(pts)
        span = (hi - lo) or 1
        left, right, top, bottom = 40, vw - 10, 24, vh - 26
        n = len(pts) - 1
        coords = []
        for idx, val in enumerate(pts):
            px = left + (right - left) * (idx / n)
            py = bottom - (bottom - top) * ((val - lo) / span)
            coords.append((round(px, 1), round(py, 1), val))
        points = " ".join(f"{x},{y}" for x, y, _ in coords)
        dots = coords

    html = Template(_HISTORY_TEMPLATE).render(
        now=_ts_human(), scans=scans, actions=actions,
        total_remediated=total_remediated, total_introduced=total_introduced,
        latest_total=latest_total, manual_actions=manual_actions,
        points=pts, polyline=points, dots=dots, vw=vw, vh=vh)
    out_path = Path(out_path) if out_path else (Path(reports_root) / "remediation_history.html")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path


def export_history_csv(reports_root, path) -> Path:
    history = load_history(reports_root)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["when", "status", "severity", "finding", "where",
                    "actor", "source", "note"])
        for a in history.get("actions", []):
            w.writerow([a.get("ts", ""), a.get("status", ""), a.get("severity", ""),
                        a.get("title", ""), a.get("where", ""), a.get("actor", ""),
                        a.get("source", ""), a.get("note", "")])
    return path
