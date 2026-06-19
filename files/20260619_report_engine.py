from __future__ import annotations

# ── report_engine.py ─────────────────────────────────────────────────────────
# Standalone report module extracted from Snyk_Scanner_GUI.py.
# Contains: data normalizers, context builder, CSV exporter, HTML template,
#           and HTML renderer.
# Both files must live in the same directory (or report_engine on sys.path).

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment

# Autoescaping environment for all HTML templates in this module.
#
# BUG FIX (filters / search / "jump to" buttons not working, report appearing
# to only contain SCA results): the HTML templates were previously rendered
# with a bare jinja2.Template(...), which does NOT autoescape by default.
# Any vulnerability title/description/recommendation text coming back from
# Snyk (or a manual remediation note) that happens to contain a `"` character
# gets inserted raw into attributes like data-text="...", which silently
# truncates the attribute at that quote and corrupts all the HTML that
# follows it in the document. That cascades into broken data-sev/data-text
# attributes on later rows, swallowed section id="..." anchors, and — once
# enough of the page is malformed — entire sections (SAST/DAST/API/Secrets)
# can end up parsed as garbage text instead of real elements, which is why
# the report can look like "only SCA shows up" even when every scan type
# ran. It's also a stored-XSS hole, since unescaped `<`/`>` get inserted as
# literal HTML (e.g. a description containing `<img src=x onerror=...>`).
#
# Fixing this at the source (autoescape=True) makes every {{ var }}
# insertion HTML-safe, regardless of where in the templates it happens.
_JINJA_ENV = Environment(autoescape=True)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# ── Text helpers for clean "recommendation to fix" extraction ────────────────
def _smart_truncate(text: str, limit: int = 2000) -> str:
    """Truncate at a word boundary (never mid-word) and mark with an ellipsis.
    Limit is intentionally large — the HTML layer handles visual truncation
    with expand/collapse, so we preserve the full text here."""
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(" .,;:—-")
    return (cut or text[:limit]) + "…"

_REMEDIATION_MARKERS = (
    "## remediation", "### remediation", "remediation:", "how to fix",
    "## how to fix", "## fix", "recommended fix:", "mitigation:",
)

def _extract_remediation(help_text: str) -> str:
    """Pull the actionable remediation guidance out of Snyk Code's SARIF
    help/markdown block, rather than the generic vulnerability-class
    description. Falls back to the most fix-relevant sentence if no
    explicit remediation section is present."""
    if not help_text:
        return ""
    low = help_text.lower()
    for marker in _REMEDIATION_MARKERS:
        idx = low.find(marker)
        if idx == -1:
            continue
        seg = help_text[idx + len(marker):]
        # Stop at the next markdown header, if any.
        nxt = re.search(r"\n#{1,4}\s", seg)
        if nxt:
            seg = seg[:nxt.start()]
        seg = seg.strip(" :\n-*")
        if seg:
            return _smart_truncate(seg, 2000)
    # No explicit section — score every sentence by how much it reads like
    # fix guidance (not just incidental word overlap with the description),
    # and keep the strongest match. Remediation sentences also tend to
    # appear later in the help text, after the vulnerability is described,
    # so ties are broken in favor of the later sentence.
    plain = re.sub(r"[#*`_]", "", help_text)
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", plain.strip()) if s.strip()]
    strong_kw = ("sanitiz", "parameteri", "escap", "to prevent", "to fix", "to avoid",
                 "instead of", "should be", "use a ", "use parameter", "allowlist",
                 "whitelist", "encode output", "validate input", "validate user")
    weak_kw = ("fix", "mitigat", "remediat", "prevent", "avoid", "should",
               "recommend", "sanitiz", "validat", "escap", "use ")
    best, best_score = "", 0
    for s in sentences:
        low_s = s.lower()
        score = 3 * sum(kw in low_s for kw in strong_kw) + sum(kw in low_s for kw in weak_kw)
        if score >= best_score and score > 0:
            best, best_score = s, score
    if best:
        return _smart_truncate(best, 2000)
    return ""

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
            ids   = v.get("identifiers", {}) or {}
            fixed = v.get("fixedIn") or []
            upgrade_path   = v.get("upgradePath") or []
            is_patchable   = bool(v.get("isPatchable"))
            is_upgradeable = bool(v.get("isUpgradable") or v.get("isUpgradeable"))
            fix_available_sca = bool(fixed or is_upgradeable or is_patchable or upgrade_path)
            if is_upgradeable and upgrade_path:
                pkg_upgrade = str(upgrade_path[0]) if upgrade_path else ""
                recommendation_sca = f"Upgrade to {', '.join(str(f) for f in fixed) if fixed else pkg_upgrade}"
            elif is_patchable:
                recommendation_sca = "Apply available Snyk patch (snyk protect)"
            elif fixed:
                recommendation_sca = f"Upgrade package — fixed in: {', '.join(str(f) for f in fixed)}"
            else:
                recommendation_sca = _smart_truncate(v.get("description") or "", 260) or "No automated fix — review manually"
            cvss_score = v.get("cvssScore") or ""
            cvss_v3    = v.get("cvssV3") or ""
            exploit    = v.get("exploit") or v.get("exploitMaturity") or ""
            disclosed  = v.get("disclosureTime") or ""
            published  = v.get("publicationTime") or ""
            issues.append({
                "severity":         (v.get("severity") or "low").lower(),
                "title":            v.get("title") or v.get("id") or "Vulnerability",
                "package":          f"{v.get('packageName','?')}@{v.get('version','?')}",
                "packageName":      v.get("packageName") or "?",
                "version":          v.get("version") or "?",
                "id":               v.get("id"),
                "cve":              ", ".join(ids.get("CVE", []) or []),
                "cwe":              ", ".join(ids.get("CWE", []) or []),
                "fixedIn":          ", ".join(str(f) for f in fixed) if fixed else "—",
                "fix_available":    fix_available_sca,
                "recommendation":   recommendation_sca,
                "is_upgradeable":   is_upgradeable,
                "is_patchable":     is_patchable,
                "path":             " > ".join((v.get("from") or [])[1:]) or "(direct)",
                "url":              v.get("url") or "",
                "description":      (v.get("description") or "")[:1200],
                "cvss_score":       cvss_score,
                "cvss_v3":          cvss_v3,
                "exploit_maturity": exploit,
                "disclosed_at":     disclosed,
                "published_at":     published,
                "language":         v.get("language") or "",
                "package_manager":  v.get("packageManager") or "",
            })
        issues.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
        out.append({
            "project":       p.get("projectName") or p.get("displayTargetFile") or p.get("path") or "(project)",
            "summary":       p.get("summary") or "",
            "uniqueCount":   p.get("uniqueCount") or len(issues),
            "issues":        issues,
            "package_manager": p.get("packageManager") or "",
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

            # ── SAST fix_available + recommendation ──────────────────────────
            # Snyk Code SARIF encodes remediation guidance in rule.help.text /
            # rule.help.markdown, rule.fullDescription.text, and result.fixes[].
            rule_props   = rule.get("properties") or {}
            rule_help    = rule.get("help") or {}
            full_desc    = rule.get("fullDescription") or {}
            # fix_available: True if Snyk provides any remediation text/fix list
            fixes_list   = result.get("fixes") or []
            help_text    = (rule_help.get("text") or rule_help.get("markdown") or
                            full_desc.get("text") or "").strip()
            fix_keywords = ("fix", "mitigat", "remediat", "prevent", "avoid",
                            "instead", "should", "recommend", "solution", "resolve")
            fix_available = bool(fixes_list or any(kw in help_text.lower()
                                                   for kw in fix_keywords))
            # Best single-line recommendation from Snyk
            recommendation = ""
            if fixes_list:
                # SARIF fixes[].description.text
                desc0 = ((fixes_list[0].get("description") or {}).get("text") or "").strip()
                if desc0: recommendation = _smart_truncate(desc0, 2000)
            if not recommendation and help_text:
                recommendation = _extract_remediation(help_text)
            if not recommendation:
                recommendation = _smart_truncate(rule_props.get("recommendation", ""), 2000)

            # ── extra SAST fields ─────────────────────────────────────────────
            confidence   = rule_props.get("precision") or result.get("rank") or ""
            impact       = rule_props.get("impact") or ""
            likelihood   = rule_props.get("likelihood") or ""
            category     = rule_props.get("category") or ""
            rule_url     = (rule.get("helpUri") or rule_props.get("url") or "")
            # CVSS-like score if present
            cvss_score   = rule_props.get("cvssScore") or rule_props.get("security-severity") or ""

            for loc in (result.get("locations") or [{}]):
                phys    = (loc.get("physicalLocation") or {}) if loc else {}
                region  = phys.get("region") or {}
                ctx     = phys.get("contextRegion") or {}
                snippet = ((ctx.get("snippet") or region.get("snippet") or {}).get("text")) or ""
                fp      = (phys.get("artifactLocation") or {}).get("uri") or "(unknown file)"
                col_start = region.get("startColumn") or ""
                col_end   = region.get("endColumn") or ""
                by_file.setdefault(fp, []).append({
                    "severity":       sev,
                    "rule":           rule_id,
                    "title":          rule.get("name") or rule.get("shortDescription", {}).get("text") or rule_id,
                    "message":        message,
                    "line":           region.get("startLine") or "?",
                    "col_start":      col_start,
                    "col_end":        col_end,
                    "cwe":            ", ".join(sorted(set(cwe))),
                    "snippet":        snippet,
                    "fix_available":  fix_available,
                    "recommendation": recommendation,
                    "confidence":     confidence,
                    "impact":         impact,
                    "likelihood":     likelihood,
                    "category":       category,
                    "rule_url":       rule_url,
                    "cvss_score":     cvss_score,
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

def export_csv(ctx: dict, path: Path, *, report_label: str = "") -> Path:
    """Export per-scan-type CSVs with industry-standard columns inside a ZIP,
    plus a unified summary sheet.

    SCA     : OWASP Dependency-Check / Snyk SCA field set (expanded)
    SAST    : OWASP ASVS / SARIF / CWE field set (with fix_available + recommendation)
    DAST    : OWASP ZAP / Burp field set (expanded)
    API     : OWASP API Security Top-10 field set (expanded)
    Secrets : NIST SP 800-53 / CWE-798 field set (expanded)
    Summary : Cross-type unified view with totals
    """
    import csv, zipfile, io

    path.parent.mkdir(parents=True, exist_ok=True)

    # ── helpers ──────────────────────────────────────────────────────────────
    def _w(buf: io.StringIO, header: list[str], rows: list[list]) -> None:
        w = csv.writer(buf)
        w.writerow(header)
        w.writerows(rows)

    def _bool(v) -> str:
        """Render a Python bool as a proper True/False string."""
        if isinstance(v, bool): return str(v)
        if isinstance(v, str):
            return "True" if v.lower() in ("true", "yes", "1") else ("False" if v.lower() in ("false", "no", "0", "") else v)
        return "True" if v else "False"

    # ── scan-level metadata ───────────────────────────────────────────────────
    scan_meta = {
        "generated_at":  ctx.get("generated_at", ""),
        "target":        ctx.get("target", ""),
        "snyk_version":  ctx.get("snyk_version", ""),
        "scan_mode":     ctx.get("scan_mode", ""),
        "total":         ctx.get("total", 0),
        "critical":      (ctx.get("counts") or {}).get("critical", 0),
        "high":          (ctx.get("counts") or {}).get("high", 0),
        "medium":        (ctx.get("counts") or {}).get("medium", 0),
        "low":           (ctx.get("counts") or {}).get("low", 0),
        "sca_total":     ctx.get("sca_total", 0),
        "code_total":    ctx.get("code_total", 0),
        "dast_total":    ctx.get("dast_total", 0),
        "api_total":     ctx.get("api_total", 0),
        "secrets_total": ctx.get("secrets_total", 0),
        "report_label":  report_label,
    }

    # ── 1. SCA — Software Composition Analysis ───────────────────────────────
    SCA_HEADER = [
        "scan_type", "report_label",
        "project", "package_manager", "language",
        "severity", "cvss_score", "cvss_v3_vector",
        "exploit_maturity",
        "vulnerable_package", "package_name", "installed_version", "fixed_version",
        "fix_available", "snyk_recommendation",
        "is_upgradeable", "is_patchable",
        "vulnerability_id", "cve", "cwe",
        "dependency_path", "transitive",
        "disclosed_at", "published_at",
        "description_preview", "advisory_url",
        # Scan-level summary columns
        "scan_total", "scan_critical", "scan_high", "scan_medium", "scan_low",
        "scan_target", "scan_generated_at",
    ]
    sca_rows: list[list] = []
    for p in ctx.get("projects", []):
        for i in p["issues"]:
            pkg_raw   = i.get("package", "")
            pkg_name  = i.get("packageName") or (pkg_raw.split("@")[0] if "@" in pkg_raw else pkg_raw)
            pkg_ver   = i.get("version") or (pkg_raw.split("@")[1] if "@" in pkg_raw else "")
            dep_path  = i.get("path", "(direct)")
            transitive = "No" if dep_path in ("(direct)", "") else "Yes"
            sca_rows.append([
                "SCA",
                report_label,
                p.get("project", ""),
                p.get("package_manager") or i.get("package_manager") or "",
                i.get("language") or "",
                i.get("severity", "").upper(),
                i.get("cvss_score", ""),
                i.get("cvss_v3", ""),
                i.get("exploit_maturity", ""),
                pkg_raw,
                pkg_name,
                pkg_ver,
                i.get("fixedIn", "—"),
                _bool(i.get("fix_available", False)),
                i.get("recommendation", ""),
                _bool(i.get("is_upgradeable", False)),
                _bool(i.get("is_patchable", False)),
                i.get("id", ""),
                i.get("cve", ""),
                i.get("cwe", ""),
                dep_path,
                transitive,
                i.get("disclosed_at", ""),
                i.get("published_at", ""),
                (i.get("description", "") or "")[:300],
                i.get("url", ""),
                # scan-level
                scan_meta["total"], scan_meta["critical"], scan_meta["high"],
                scan_meta["medium"], scan_meta["low"],
                scan_meta["target"], scan_meta["generated_at"],
            ])

    # ── 2. SAST — Static Application Security Testing ───────────────────────
    SAST_HEADER = [
        "scan_type", "report_label",
        "file_path", "line_start", "col_start", "col_end",
        "severity", "cvss_score",
        "rule_id", "rule_name", "category",
        "cwe", "owasp_category",
        "fix_available", "snyk_recommendation",
        "confidence", "impact", "likelihood",
        "message", "code_snippet_preview",
        "rule_url",
        # Scan-level summary columns
        "scan_total", "scan_critical", "scan_high", "scan_medium", "scan_low",
        "scan_target", "scan_generated_at",
    ]
    sast_rows: list[list] = []
    _SAST_OWASP = {
        "CWE-79":  "A03 Injection", "CWE-89":  "A03 Injection",
        "CWE-94":  "A03 Injection", "CWE-78":  "A03 Injection",
        "CWE-77":  "A03 Injection", "CWE-918": "A10 SSRF",
        "CWE-611": "A05 Security Misconfiguration",
        "CWE-22":  "A01 Broken Access Control", "CWE-23": "A01 Broken Access Control",
        "CWE-352": "A01 Broken Access Control", "CWE-862": "A01 Broken Access Control",
        "CWE-863": "A01 Broken Access Control",
        "CWE-502": "A08 Insecure Deserialization",
        "CWE-327": "A02 Cryptographic Failures", "CWE-326": "A02 Cryptographic Failures",
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
            snippet   = (i.get("snippet", "") or "").replace("\n", " ").strip()[:300]
            sast_rows.append([
                "SAST",
                report_label,
                f.get("file", ""),
                str(i.get("line", "")),
                str(i.get("col_start", "")),
                str(i.get("col_end", "")),
                i.get("severity", "").upper(),
                i.get("cvss_score", ""),
                i.get("rule", ""),
                i.get("title", ""),
                i.get("category", ""),
                cwe_raw,
                owasp_cat,
                _bool(i.get("fix_available", False)),
                i.get("recommendation", ""),
                i.get("confidence", ""),
                i.get("impact", ""),
                i.get("likelihood", ""),
                (i.get("message", "") or "")[:400],
                snippet,
                i.get("rule_url", ""),
                # scan-level
                scan_meta["total"], scan_meta["critical"], scan_meta["high"],
                scan_meta["medium"], scan_meta["low"],
                scan_meta["target"], scan_meta["generated_at"],
            ])

    # ── 3. DAST — Dynamic Application Security Testing ──────────────────────
    _DAST_OWASP = {
        "auth":     "API2 Broken Authentication",
        "injection":"API8 Injection", "csrf":     "API6 Mass Assignment",
        "headers":  "API7 Security Misconfiguration",
        "ssl":      "API7 Security Misconfiguration",
        "redirect": "API3 Excessive Data Exposure",
        "xss":      "API8 Injection", "sqli":     "API8 Injection",
        "cors":     "API7 Security Misconfiguration",
        "info":     "API9 Improper Assets Management",
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
    DAST_HEADER = [
        "scan_type", "report_label",
        "severity", "owasp_api_top10", "category",
        "title", "url", "http_method", "parameter",
        "cwe",
        "fix_available", "snyk_recommendation",
        "status_code", "response_time_ms",
        "evidence_preview", "solution_hint",
        "dast_target", "dast_profile",
        "pages_visited", "forms_discovered",
        # Scan-level summary columns
        "scan_total", "scan_critical", "scan_high", "scan_medium", "scan_low",
        "scan_target", "scan_generated_at",
    ]
    dast_meta = ctx.get("dast") or {}
    dast_rows: list[list] = []
    for d in dast_meta.get("findings", []):
        cat = (d.get("category") or "").lower()
        hint = _DAST_SOLUTION.get(cat, "")
        fix_avail_dast = bool(hint)
        dast_rows.append([
            "DAST",
            report_label,
            d.get("severity", "").upper(),
            _DAST_OWASP.get(cat, ""),
            d.get("category", ""),
            d.get("title", ""),
            d.get("url", ""),
            d.get("method", ""),
            d.get("param", ""),
            d.get("cwe", ""),
            _bool(fix_avail_dast),
            hint,
            d.get("status_code", ""),
            d.get("response_time_ms", ""),
            (d.get("evidence", "") or "")[:400],
            hint,
            dast_meta.get("target", ""),
            dast_meta.get("profile", ""),
            dast_meta.get("pages_visited", ""),
            dast_meta.get("forms_discovered", ""),
            # scan-level
            scan_meta["total"], scan_meta["critical"], scan_meta["high"],
            scan_meta["medium"], scan_meta["low"],
            scan_meta["target"], scan_meta["generated_at"],
        ])

    # ── 4. API Security ──────────────────────────────────────────────────────
    API_HEADER = [
        "scan_type", "report_label",
        "severity", "owasp_api_top10", "category",
        "title", "endpoint_url", "http_method", "parameter",
        "cwe", "authentication_required",
        "fix_available", "snyk_recommendation",
        "status_code", "response_time_ms",
        "evidence_preview", "solution_hint",
        "api_spec_source", "api_profile",
        "endpoints_tested", "endpoints_total",
        # Scan-level summary columns
        "scan_total", "scan_critical", "scan_high", "scan_medium", "scan_low",
        "scan_target", "scan_generated_at",
    ]
    api_meta = ctx.get("api") or {}
    api_rows: list[list] = []
    for d in api_meta.get("findings", []):
        cat = (d.get("category") or "").lower()
        hint = _DAST_SOLUTION.get(cat, "")
        fix_avail_api = bool(hint)
        api_rows.append([
            "API",
            report_label,
            d.get("severity", "").upper(),
            _DAST_OWASP.get(cat, ""),
            d.get("category", ""),
            d.get("title", ""),
            d.get("url", ""),
            d.get("method", ""),
            d.get("param", ""),
            d.get("cwe", ""),
            d.get("auth_required", ""),
            _bool(fix_avail_api),
            hint,
            d.get("status_code", ""),
            d.get("response_time_ms", ""),
            (d.get("evidence", "") or "")[:400],
            hint,
            api_meta.get("spec_source", ""),
            api_meta.get("profile", ""),
            api_meta.get("endpoints_tested", ""),
            api_meta.get("endpoints_total", ""),
            # scan-level
            scan_meta["total"], scan_meta["critical"], scan_meta["high"],
            scan_meta["medium"], scan_meta["low"],
            scan_meta["target"], scan_meta["generated_at"],
        ])

    # ── 5. Secrets ────────────────────────────────────────────────────────────
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
        "scan_type", "report_label",
        "severity", "secret_type", "cwe", "owasp_top10",
        "file_path", "line_number", "commit_scope",
        "secret_match_redacted", "context_snippet",
        "engine",
        "fix_available", "snyk_recommendation",
        # Scan-level summary columns
        "scan_total", "scan_critical", "scan_high", "scan_medium", "scan_low",
        "scan_target", "scan_generated_at",
    ]
    secrets_meta = ctx.get("secrets") or {}
    secrets_rows: list[list] = []
    for s in secrets_meta.get("findings", []):
        stype = (s.get("secret_type") or s.get("rule", "")).strip().lower()
        cwe   = s.get("cwe") or _SECRET_CWE.get(stype, "CWE-798")
        remediaton_text = "ROTATE credential immediately; purge from git history (git-filter-repo / BFG)"
        secrets_rows.append([
            "Secrets",
            report_label,
            s.get("severity", "HIGH").upper(),
            s.get("secret_type") or s.get("rule", ""),
            cwe,
            "A07 Identification & Authentication Failures",
            s.get("file", ""),
            s.get("line", "?"),
            "",
            s.get("match", ""),
            (s.get("context", "") or "").replace("\n", " ").strip()[:400],
            s.get("engine", ""),
            _bool(True),   # Always True — rotation IS the fix
            remediaton_text,
            # scan-level
            scan_meta["total"], scan_meta["critical"], scan_meta["high"],
            scan_meta["medium"], scan_meta["low"],
            scan_meta["target"], scan_meta["generated_at"],
        ])

    # ── 6. Summary sheet — cross-type with totals + fix_available + recommendation
    SUMMARY_HEADER = [
        "scan_type", "report_label",
        "severity", "title", "location",
        "cwe", "cve_or_id",
        "fix_available", "snyk_recommendation",
        "advisory_url",
        # Totals block
        "total_findings", "total_critical", "total_high", "total_medium", "total_low",
        "sca_count", "sast_count", "dast_count", "api_count", "secrets_count",
        "scan_target", "scan_mode", "snyk_version", "scan_generated_at",
    ]
    totals_block = [
        scan_meta["total"], scan_meta["critical"], scan_meta["high"],
        scan_meta["medium"], scan_meta["low"],
        scan_meta["sca_total"], scan_meta["code_total"],
        scan_meta["dast_total"], scan_meta["api_total"], scan_meta["secrets_total"],
        scan_meta["target"], scan_meta["scan_mode"],
        scan_meta["snyk_version"], scan_meta["generated_at"],
    ]
    summary_rows: list[list] = []
    for r in sca_rows:
        # r cols: scan_type(0), report_label(1), project(2), pkg_mgr(3), lang(4),
        #   severity(5), cvss(6), cvss_v3(7), exploit(8), pkg_raw(9), pkg_name(10),
        #   pkg_ver(11), fixedIn(12), fix_available(13), recommendation(14),
        #   is_upgradeable(15), is_patchable(16), id(17), cve(18), cwe(19),
        #   dep_path(20), transitive(21), disclosed(22), published(23), desc(24), url(25)
        summary_rows.append([
            r[0], r[1],
            r[5], r[17] or r[10],           # severity, vuln_id or pkg_name
            f"{r[2]} · {r[9]}",             # location = project · package
            r[19], r[18],                   # cwe, cve
            r[13], r[14],                   # fix_available, recommendation
            r[25],                          # url
        ] + totals_block)
    for r in sast_rows:
        # r cols: scan_type(0), report_label(1), file(2), line(3), col_start(4), col_end(5),
        #   severity(6), cvss(7), rule_id(8), rule_name(9), category(10), cwe(11),
        #   owasp(12), fix_available(13), recommendation(14), confidence(15),
        #   impact(16), likelihood(17), message(18), snippet(19), rule_url(20)
        summary_rows.append([
            r[0], r[1],
            r[6], r[9],                     # severity, rule_name
            f"{r[2]}:{r[3]}",               # location = file:line
            r[11], r[8],                    # cwe, rule_id
            r[13], r[14],                   # fix_available, recommendation
            r[20],                          # rule_url
        ] + totals_block)
    for r in dast_rows:
        # r cols: scan_type(0), report_label(1), severity(2), owasp(3), category(4),
        #   title(5), url(6), method(7), param(8), cwe(9),
        #   fix_available(10), recommendation(11), status_code(12), resp_ms(13),
        #   evidence(14), solution(15)
        summary_rows.append([
            r[0], r[1],
            r[2], r[5],
            r[6],
            r[9], "",
            r[10], r[11],
            "",
        ] + totals_block)
    for r in api_rows:
        # same column layout as dast_rows for the leading fields
        summary_rows.append([
            r[0], r[1],
            r[2], r[5],
            r[6],
            r[9], "",
            r[11], r[12],
            "",
        ] + totals_block)
    for r in secrets_rows:
        # r cols: scan_type(0), report_label(1), severity(2), secret_type(3),
        #   cwe(4), owasp(5), file(6), line(7), commit(8), match(9),
        #   context(10), engine(11), fix_available(12), recommendation(13)
        summary_rows.append([
            r[0], r[1],
            r[2], r[3],
            f"{r[6]}:{r[7]}",
            r[4], "",
            r[12], r[13],
            "",
        ] + totals_block)

    # ── Write ZIP with individual sheets ─────────────────────────────────────
    # Reuse the report's own basename (e.g. "secrets+checo_20260616", the same
    # name used for the top-level .html/.csv) as the folder inside the ZIP too,
    # so every artifact belonging to one report shares one consistent name
    # instead of the bundle having a separately-computed slug+timestamp.
    bundle_name = path.stem or (report_label.replace("+", "_").replace(" ", "_") if report_label else "scan")
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
            zf.writestr(f"{bundle_name}/{fname}", buf.getvalue())

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
.section-head{display:flex;align-items:baseline;gap:10px;margin:26px 0 12px;scroll-margin-top:104px;cursor:pointer;user-select:none}
.section-head:hover h3{color:var(--ac)}
.section-head h3{margin:0;font-size:18px;transition:color .12s}
.section-head .chev{display:inline-block;font-size:11px;color:var(--mu);transition:transform .15s ease;transform:rotate(0deg)}
.section-head.collapsed .chev{transform:rotate(-90deg)}
.sec-body{transition:none}
.sec-body.collapsed{display:none}
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
.fix{color:#15803d;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;font-size:12px;margin-top:6px;padding:6px 9px;max-width:720px;line-height:1.45}
.fix b{color:#166534}
.sev{display:inline-block;padding:3px 10px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase}
pre.snippet{background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:10px;overflow:auto;font-size:12px;max-height:200px;margin:8px 0 0}
.empty{text-align:center;padding:34px;color:var(--mu);border:1px dashed var(--bd2);border-radius:var(--r)}
footer{text-align:center;color:var(--mu);font-size:12px;padding:30px 0 0}
.hide{display:none!important}
/* ── Index nav ──────────────────────────────────────────────────── */
.idx{position:sticky;top:54px;z-index:4;background:rgba(255,255,255,.95);backdrop-filter:blur(6px);
  border-bottom:1px solid var(--bd);padding:7px 0;margin:0 0 10px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.idx a{font-size:12px;color:var(--mu);padding:4px 10px;border-radius:999px;border:1px solid var(--bd);text-decoration:none;white-space:nowrap}
.idx a:hover{background:var(--ac);color:#fff;border-color:var(--ac)}
.idx .idx-sep{color:var(--bd2);font-size:10px}
/* ── Back to top ──────────────────────────────────────────────────── */
#btt{position:fixed;bottom:28px;right:28px;z-index:99;background:var(--ac);color:#fff;border:none;
  border-radius:50%;width:40px;height:40px;font-size:18px;cursor:pointer;display:none;
  box-shadow:0 2px 10px rgba(0,0,0,.18);line-height:40px;text-align:center}
#btt.vis{display:block}
/* ── Expandable fix ──────────────────────────────────────────────── */
.fix-short{display:block}.fix-full{display:none}
.fix-expand{cursor:pointer;font-size:10px;color:var(--ac);margin-left:4px;opacity:.7;user-select:none}
.fix-expand:hover{opacity:1}
/* ── Filter: hide whole group when empty ─────────────────────────── */
details.group.grp-hidden{display:none!important}
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

{% macro fix_cell(txt) %}{% if txt %}
  {% set tlen = txt | length %}
  {% if tlen > 240 %}
  <div class="fix"><b>🛠 Fix:</b>
    <span class="fix-short">{{ txt[:240] }}<span class="fix-expand" onclick="var p=this.parentNode,f=p.nextElementSibling;p.style.display='none';f.style.display='inline'" title="See full recommendation">… <b style="font-size:10px">▼ see more</b></span></span>
    <span class="fix-full" style="display:none">{{ txt }}<span class="fix-expand" onclick="var f=this.parentNode,p=f.previousElementSibling;f.style.display='none';p.style.display='inline'" title="Collapse"> <b style="font-size:10px">▲ collapse</b></span></span>
  </div>
  {% else %}<div class="fix"><b>🛠 Fix:</b> {{ txt }}</div>{% endif %}
{% endif %}{% endmacro %}

<button id="btt" onclick="window.scrollTo({top:0,behavior:'smooth'})" title="Back to top">↑</button>
<div class="idx">
  <span style="font-size:11px;font-weight:700;color:var(--mu);margin-right:2px">Jump to:</span>
  {% if sca_total %}<a href="#sec-sca">🔍 SCA <b>{{ sca_total }}</b></a>{% endif %}
  {% if code_total %}<a href="#sec-sast">🧬 SAST <b>{{ code_total }}</b></a>{% endif %}
  {% if dast_total %}<a href="#sec-dast">🌐 DAST <b>{{ dast_total }}</b></a>{% endif %}
  {% if api_total %}<a href="#sec-api">🔌 API <b>{{ api_total }}</b></a>{% endif %}
  {% if secrets_total %}<a href="#sec-secrets">🔑 Secrets <b>{{ secrets_total }}</b></a>{% endif %}
</div>

<div class="section-head" id="sec-sca"><span class="chev">▾</span><h3>Open-source (SCA)</h3><span class="count">{{ sca_total }}</span>
  <span class="hint">{{ projects|selectattr('issues')|list|length }} project{{ '' if projects|selectattr('issues')|list|length==1 else 's' }} with findings{% if state_timestamps and state_timestamps.sca %}  ·  last scan {{ state_timestamps.sca[:16] }}{% endif %}</span></div>
<div class="sec-body">
{% if not projects %}<div class="empty">No manifests detected or no vulnerabilities found.</div>{% endif %}
{% for p in projects %}{% if p.issues or p.error %}<details class="group sca-group" open>
  <summary>
    <span class="gt mono" title="{{ p.project }}">
      📄 {{ p.project.split('/')[-1] if '/' in p.project else (p.project.split('\\')[-1] if '\\' in p.project else p.project) }}
      <span style="font-weight:400;font-size:10px;opacity:.7;margin-left:6px">{{ p.project }}</span>
    </span>
    <span class="gm">{{ mini(p.issues) }}</span>
  </summary>
  {% if p.error %}<div style="padding:16px;color:var(--mu)">Error: {{ p.error }}</div>
  {% elif p.issues %}<div class="table-wrap"><table>
    <thead><tr><th>Severity</th><th>Vulnerable Package</th><th>Installed ver.</th><th>Dependency chain</th><th>Fixed in</th><th>Title / Advisory</th><th>CVE</th><th>CWE</th><th>Transitive?</th></tr></thead><tbody>
    {% for i in p.issues %}
      {% set pkg_name = i.package.split('@')[0] if '@' in i.package else i.package %}
      {% set pkg_ver  = i.package.split('@')[1] if '@' in i.package else '' %}
      {% set dep_path = i.path or '(direct)' %}
      {% set is_trans = dep_path not in ('(direct)', '') %}
    <tr class="row" data-sev="{{ i.severity }}"
      data-text="{{ (i.package~' '~i.title~' '~i.cve~' '~i.cwe~' '~dep_path~' '~p.project~' '~(i.recommendation or ''))|lower }}">
      <td><span class="sev {{ i.severity }}">{{ i.severity }}</span></td>
      <td>
        <code style="font-size:12px">{{ pkg_name }}</code>
        <div class="desc" style="font-size:10px;margin-top:2px;color:var(--mu)" title="{{ p.project }}">
          📄 {{ p.project.split('/')[-1] if '/' in p.project else (p.project.split('\\')[-1] if '\\' in p.project else p.project) }}
        </div>
      </td>
      <td><code>{{ pkg_ver or '—' }}</code></td>
      <td class="mono" style="font-size:10px;color:var(--mu);max-width:220px;word-break:break-all" title="{{ dep_path }}">
        {% if is_trans %}{{ dep_path }}{% else %}<span style="color:var(--low)">(direct)</span>{% endif %}
      </td>
      <td>{% if i.fixedIn and i.fixedIn != '—' %}<span style="color:var(--low);font-weight:600">{{ i.fixedIn }}</span>{% else %}<span style="color:var(--mu)">—</span>{% endif %}</td>
      <td>{% if i.url %}<a href="{{ i.url }}" target="_blank">{{ i.title }}</a>{% else %}{{ i.title }}{% endif %}
        {% if i.description %}<div class="desc">{{ i.description[:300] }}</div>{% endif %}
        {{ fix_cell(i.recommendation) }}</td>
      <td>{% if i.cve %}<code style="color:var(--crit)">{{ i.cve }}</code>{% else %}<span style="color:var(--mu)">—</span>{% endif %}</td>
      <td><code>{{ i.cwe or '—' }}</code></td>
      <td style="text-align:center">{% if is_trans %}<span class="mini medium">indirect</span>{% else %}<span class="mini low">direct</span>{% endif %}</td>
    </tr>{% endfor %}
    </tbody></table></div>
  {% endif %}
</details>{% endif %}{% endfor %}
</div>

<div class="section-head" id="sec-sast"><span class="chev">▾</span><h3>Static code (SAST)</h3><span class="count">{{ code_total }}</span>
  <span class="hint">{{ files|length }} file{{ '' if files|length==1 else 's' }}{% if state_timestamps and state_timestamps.code %}  ·  last scan {{ state_timestamps.code[:16] }}{% endif %}</span></div>
<div class="sec-body">
{% if not files %}<div class="empty">No SAST issues found.</div>{% endif %}
{% for f in files %}<details class="group sast-group" open>
  <summary>
    <span class="gt mono" title="{{ f.file }}">
      🧬 {{ f.file.split('/')[-1] if '/' in f.file else (f.file.split('\\')[-1] if '\\' in f.file else f.file) }}
      <span style="font-weight:400;font-size:10px;opacity:.7;margin-left:6px">{{ f.file }}</span>
    </span>
    <span class="gm">{{ mini(f.issues) }}</span>
  </summary>
  <div class="table-wrap"><table>
    <thead><tr><th>Severity</th><th>Rule ID</th><th>Rule name</th><th>File · Line</th><th>CWE</th><th>OWASP</th><th>Message / Fix</th><th>Snippet</th></tr></thead><tbody>
    {% set _SAST_OWASP = {'CWE-79':'A03 Injection','CWE-89':'A03 Injection','CWE-94':'A03 Injection','CWE-78':'A03 Injection','CWE-918':'A10 SSRF','CWE-611':'A05 Misconfiguration','CWE-22':'A01 Broken Access Control','CWE-352':'A01 Broken Access Control','CWE-862':'A01 Broken Access Control','CWE-502':'A08 Insecure Deserialization','CWE-327':'A02 Crypto Failures','CWE-326':'A02 Crypto Failures','CWE-798':'A07 Auth Failures','CWE-259':'A07 Auth Failures','CWE-287':'A07 Auth Failures','CWE-532':'A09 Logging Failures'} %}
    {% for i in f.issues %}
      {% set cwe_key = i.cwe.split(',')[0].strip().upper() %}
      {% set owasp_cat = _SAST_OWASP.get(cwe_key, '') %}
      {% set fname_short = f.file.split('/')[-1] if '/' in f.file else (f.file.split('\\')[-1] if '\\' in f.file else f.file) %}
    <tr class="row" data-sev="{{ i.severity }}"
      data-text="{{ (i.rule~' '~i.title~' '~i.message~' '~i.cwe~' '~f.file~' '~(i.recommendation or ''))|lower }}">
      <td><span class="sev {{ i.severity }}">{{ i.severity }}</span></td>
      <td><code>{{ i.rule }}</code></td>
      <td style="font-weight:600">{{ i.title or i.rule }}</td>
      <td class="mono" style="font-size:10px;white-space:nowrap">
        <span style="color:var(--mu)" title="{{ f.file }}">{{ fname_short }}</span><br>
        <code style="color:var(--ac)">:{{ i.line }}</code>
        {% if i.col_start %}<span style="color:var(--mu);font-size:9px"> col {{ i.col_start }}{% if i.col_end and i.col_end != i.col_start %}–{{ i.col_end }}{% endif %}</span>{% endif %}
      </td>
      <td><code>{{ i.cwe or '—' }}</code></td>
      <td style="font-size:11px;color:var(--mu)">{{ owasp_cat or '—' }}</td>
      <td>{{ i.message }}
        {{ fix_cell(i.recommendation) }}</td>
      <td>{% if i.snippet %}<pre class="snippet">{{ i.snippet[:500] }}</pre>{% else %}<span style="color:var(--mu)">—</span>{% endif %}</td>
    </tr>{% endfor %}
    </tbody></table></div>
</details>{% endfor %}
</div>

{% if dast.findings or dast.pages_visited %}
<div class="section-head" id="sec-dast"><span class="chev">▾</span><h3>Dynamic (DAST) — {{ dast.target }}</h3>
  <span class="count">{{ dast_total }}</span>
  <span class="hint">{{ dast.pages_visited }} pages · {{ dast.profile }}{% if state_timestamps and state_timestamps.dast %}  ·  last scan {{ state_timestamps.dast[:16] }}{% endif %}</span></div>
<div class="sec-body">
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
</details>{% endif %}
</div>
{% endif %}

{% if api.findings or api.endpoints_tested %}
<div class="section-head" id="sec-api"><span class="chev">▾</span><h3>API Security</h3>
  <span class="count">{{ api_total }}</span>
  <span class="hint">{{ api.endpoints_tested }}/{{ api.endpoints_total }} endpoints · {{ api.profile }}{% if state_timestamps and state_timestamps.api %}  ·  last scan {{ state_timestamps.api[:16] }}{% endif %}</span></div>
<div class="sec-body">
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
</details>{% endif %}
</div>
{% endif %}

{% if secrets.findings or secrets.scanned_files %}
<div class="section-head" id="sec-secrets"><span class="chev">▾</span><h3>🔑 Secrets / Hard-coded Credentials</h3>
  <span class="count">{{ secrets_total }}</span>
  <span class="hint">{{ secrets.scanned_files }} files scanned · engine: {{ secrets.engine or 'built-in' }}{% if state_timestamps and state_timestamps.secrets %}  ·  last scan {{ state_timestamps.secrets[:16] }}{% endif %}</span></div>
<div class="sec-body">
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
</details>{% endif %}
</div>
{% endif %}

<footer>Generated by Vulnerability Scanner · Snyk {{ snyk_version or '?' }} · {{ generated_at }}</footer>
</div>
<script>
(function(){
  var rows=document.querySelectorAll('.row'),
      chips=document.querySelectorAll('.chip'),
      search=document.getElementById('search'),
      btt=document.getElementById('btt');
  var curSev='all',curQ='';

  function filter(){
    rows.forEach(function(r){
      var sev=r.dataset.sev,txt=r.dataset.text||'';
      var ok=(curSev==='all'||sev===curSev)&&(!curQ||txt.includes(curQ));
      r.classList.toggle('hide',!ok);
    });
    // Hide entire group <details> when all its rows are hidden
    document.querySelectorAll('details.group').forEach(function(g){
      var allRows=g.querySelectorAll('.row');
      if(allRows.length===0){g.classList.remove('grp-hidden');return;}
      var anyVis=false;
      allRows.forEach(function(r){if(!r.classList.contains('hide'))anyVis=true;});
      g.classList.toggle('grp-hidden',!anyVis);
    });
  }

  chips.forEach(function(c){
    c.onclick=function(){
      chips.forEach(function(x){x.classList.remove('active');});
      c.classList.add('active');curSev=c.dataset.sev;filter();
    };
  });
  if(search){
    search.oninput=function(){curQ=search.value.toLowerCase();filter();};
    document.addEventListener('keydown',function(e){
      if(e.key==='/'&&document.activeElement!==search){e.preventDefault();search.focus();}
    });
  }
  // Back-to-top button
  if(btt){
    window.addEventListener('scroll',function(){
      btt.classList.toggle('vis',window.scrollY>400);
    });
  }

  // Collapsible sections — click a section title (SCA, SAST, DAST, …) to
  // collapse/expand everything under it.
  function expandSection(head){
    head.classList.remove('collapsed');
    var body=head.nextElementSibling;
    if(body&&body.classList.contains('sec-body'))body.classList.remove('collapsed');
  }
  document.querySelectorAll('.section-head').forEach(function(head){
    head.addEventListener('click',function(){
      var body=head.nextElementSibling;
      if(!body||!body.classList.contains('sec-body'))return;
      head.classList.toggle('collapsed');
      body.classList.toggle('collapsed');
    });
  });
  // "Jump to" links should auto-expand a collapsed section so the target
  // is actually visible after the anchor scroll happens.
  document.querySelectorAll('.idx a[href^="#"]').forEach(function(a){
    a.addEventListener('click',function(){
      var head=document.getElementById(a.getAttribute('href').slice(1));
      if(head)expandSection(head);
    });
  });
  // Deep-link support: if the page loads (or the hash changes) pointing at
  // a section, expand it automatically.
  function expandFromHash(){
    if(!location.hash)return;
    var head=document.getElementById(location.hash.slice(1));
    if(head&&head.classList.contains('section-head'))expandSection(head);
  }
  window.addEventListener('hashchange',expandFromHash);
  expandFromHash();
})();
</script>
</body></html>
"""

def render_html(ctx: dict, out_dir: Path, filename: str = "report.html") -> Path:
    html = _JINJA_ENV.from_string(REPORT_TEMPLATE).render(**ctx)
    path = out_dir / filename
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


def _fmt_ts(value: Any) -> str:
    """Normalise any stored timestamp to 'YYYY-MM-DD HH:MM' for display."""
    s = str(value or "").strip()
    if not s:
        return "—"
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y%m%d_%H%M%S",
                "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d %H:%M")
        except ValueError:
            continue
    return s


def _short_date(value: Any) -> str:
    """Compact 'MM-DD' date used for the trend-chart x-axis labels."""
    s = _fmt_ts(value)
    return s[5:10] if len(s) >= 10 else s


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
  {% for px,py,val,dt in dots %}
  <circle cx="{{ px }}" cy="{{ py }}" r="3.5" fill="#F5A800"/>
  <text x="{{ px }}" y="{{ py-9 }}" font-size="11" fill="#6b7280" text-anchor="middle">{{ val }}</text>
  <text x="{{ px }}" y="{{ vh-9 }}" font-size="10" fill="#9ca3af" text-anchor="middle">{{ dt }}</text>
  {% endfor %}
</svg></div>
{% endif %}

<div class="panel"><h2>Scan timeline</h2>
{% if not scans %}<div class="empty">No scans recorded yet.</div>{% else %}
<table><thead><tr><th>When</th><th>Mode</th><th>Open</th><th>Critical</th><th>High</th>
<th>Remediated</th><th>New</th><th>By</th></tr></thead><tbody>
{% for s in scans|reverse %}
<tr><td>{{ s.ts_fmt }}</td><td><code>{{ s.mode|upper }}</code></td>
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
<tr><td>{{ a.ts_fmt }}</td>
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

    # Normalise timestamps to a clean, human-readable date for display.
    for s in scans:
        s["ts_fmt"] = _fmt_ts(s.get("ts"))
    for a in actions:
        a["ts_fmt"] = _fmt_ts(a.get("ts"))

    total_remediated = sum(s.get("remediated_count", 0) for s in scans)
    total_introduced = sum(s.get("introduced_count", 0) for s in scans)
    latest_total = scans[-1].get("total", 0) if scans else 0
    manual_actions = sum(1 for a in actions if a.get("source") == "manual")

    # Build a simple SVG line chart of open-issue totals over time.
    vw, vh = 900, 240
    pts = [s.get("total", 0) for s in scans]
    date_labels = [_short_date(s.get("ts")) for s in scans]
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
            coords.append((round(px, 1), round(py, 1), val, date_labels[idx]))
        points = " ".join(f"{x},{y}" for x, y, _, _ in coords)
        dots = coords

    html = _JINJA_ENV.from_string(_HISTORY_TEMPLATE).render(
        now=_ts_human(), scans=scans, actions=actions,
        total_remediated=total_remediated, total_introduced=total_introduced,
        latest_total=latest_total, manual_actions=manual_actions,
        points=pts, polyline=points, dots=dots, vw=vw, vh=vh)
    out_path = Path(out_path) if out_path else (Path(reports_root) / "remediation_history.html")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path
