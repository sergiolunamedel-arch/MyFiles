"""snyk_dast_api.py — DAST + API security scanning backed by Snyk API & Web (Probely).

This module is a DROP-IN REPLACEMENT for the engine half of the old ``dast_api``.
It keeps the exact same public contract so nothing else in the app has to change:

    DastConfig, ApiConfig            (dataclasses, now with Probely fields)
    run_dast(cfg, out_dir, log, cancel, progress) -> (summary_dict, path)
    run_api (cfg, out_dir, log, cancel, progress) -> (summary_dict, path)

WHAT CHANGED vs. the local engine
---------------------------------
* The scan is NO LONGER performed locally. ``run_dast`` / ``run_api`` now drive
  Snyk API & Web (the DAST/API product Snyk built on Probely) over its REST API
  at https://api.probely.com. The local urllib crawler + injection probes are
  gone — that is the "escaneo local" the rewrite was asked to remove.
* The Selenium login/logout RECORDER is reused as-is (it still runs locally) but
  only to PRODUCE a login sequence; the recorded steps are converted and uploaded
  to the Probely target so the cloud scanner can authenticate. See
  ``macro_to_probely_sequence`` and the ``probely_login_sequence_path`` config.
* The spec-parsing helpers used by the API tab's PREVIEW pane are re-exported
  unchanged (parsing/converting a spec for display is not "scanning").

OPERATIONAL PRECONDITIONS (enforced + logged, not silently skipped)
------------------------------------------------------------------
1. A Snyk API & Web (Probely) API key. Generated in the app, sent as
   ``Authorization: JWT <token>``. Put it in ``cfg.probely_token``.
2. The target DOMAIN must be VERIFIED in Probely, or scans are treated as
   malicious. Unverified targets are aborted with a clear finding + the
   verification token in the log.
3. The target must be reachable from Probely's cloud. Internal/non-prod hosts
   need Probely's on-prem scanning agent (out of scope for this module).

No third-party dependencies: networking is plain ``urllib`` to match the rest of
the codebase.
"""

from __future__ import annotations

import base64
import json
import mimetypes
import os
import re
import ssl
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse, urlencode, urljoin, parse_qsl
from urllib.request import Request, build_opener, HTTPSHandler
from urllib.error import HTTPError, URLError

from dast_api import (  # noqa: F401  (re-exported on purpose)
    _MACRO_JS, _MACRO_DRAIN_JS, _LOGOUT_CAPTURE_JS,
    detect_browsers, prewarm_driver, _make_driver,
    _replay_login_macro, analyze_login_macro,
    record_macro_work, record_logout_work, test_logout_work,
    _api_load_spec, _api_base_url, _api_operations, _make_opener,
    DastConfig as _BaseDastConfig, ApiConfig as _BaseApiConfig,
)


@dataclass
class DastConfig(_BaseDastConfig):
    probely_token: str = ""
    probely_api_base: str = "https://api.probely.com"
    probely_auth_scheme: str = "JWT"
    probely_target_id: str = ""
    probely_scan_profile: str = ""
    probely_login_sequence_path: str = ""
    probely_poll_interval: float = 15.0
    probely_max_wait_minutes: float = 180.0
    probely_reuse_by_url: bool = True
    probely_blacklist: str = ""
    probely_logout_detection: bool = True
    probely_check_session_url: str = ""
    probely_logout_markers: str = ""
    probely_logout_condition: str = "any"
    probely_logout_url_detector: bool = True
    probely_logout_code_detector: bool = True
    probely_logout_selector: str = ""
    probely_login_url: str = ""
    probely_protect_session: bool = True
    probely_form_login: str = "auto"
    probely_form_login_check_pattern: str = ""
    probely_form_submit_selector: str = ""
    probely_region: str = ""
    probely_2fa_enabled: bool = False
    probely_otp_secret: str = ""
    probely_otp_field: str = ""
    probely_otp_submit: str = ""
    probely_otp_algorithm: str = "SHA1"
    probely_otp_digits: int = 6
    probely_reduced_scopes: str = ""
    probely_extra_hosts: str = ""
    probely_ignore_blackout: bool = False
    probely_compliance_report: str = ""
    probely_agent_warn: bool = True
    probely_require_verified: bool = False
    probely_logout_body_markers: str = ""
    probely_logout_header_markers: str = ""
    # ── Slot-pool orchestration ───────────────────────────────────────────────
    probely_orchestrate: bool = True
    probely_pool_size: int = 5
    probely_slot_cooldown_minutes: float = 60.0
    probely_ledger_path: str = ""


@dataclass
class ApiConfig(_BaseApiConfig):
    probely_token: str = ""
    probely_api_base: str = "https://api.probely.com"
    probely_auth_scheme: str = "JWT"
    probely_target_id: str = ""
    probely_scan_profile: str = ""
    probely_login_sequence_path: str = ""
    probely_poll_interval: float = 15.0
    probely_max_wait_minutes: float = 180.0
    probely_reuse_by_url: bool = True
    probely_protect_session: bool = True
    probely_region: str = ""
    probely_reduced_scopes: str = ""
    probely_ignore_blackout: bool = False
    probely_compliance_report: str = ""
    probely_check_login: bool = True
    probely_require_verified: bool = False
    probely_api_schema_type: str = ""
    probely_api_login_url: str = ""
    probely_api_login_payload: str = ""
    probely_api_login_media_type: str = "application/json"
    probely_api_login_token_field: str = ""
    probely_api_login_token_param: str = "Authorization"
    probely_api_login_token_prefix: str = ""
    probely_api_login_place: str = "header"
    # ── Slot-pool orchestration ───────────────────────────────────────────────
    probely_orchestrate: bool = True
    probely_pool_size: int = 5
    probely_slot_cooldown_minutes: float = 60.0
    probely_ledger_path: str = ""


def _norm_severity(prob_sev: Any, cvss: Any) -> str:
    try:
        s = int(prob_sev)
    except (TypeError, ValueError):
        s = 0
    try:
        c = float(cvss)
    except (TypeError, ValueError):
        c = 0.0
    if s >= 30:
        return "critical" if c >= 9.0 else "high"
    if s >= 20:
        return "medium"
    if s >= 10:
        return "low"
    return "low"


_CATEGORY_KEYWORDS = (
    ("sql", "sqli"), ("cross-site scripting", "xss"), ("xss", "xss"),
    ("authentication", "auth"), ("authorization", "auth"),
    ("bola", "auth"), ("object level", "auth"),
    ("redirect", "redirect"), ("ssrf", "ssrf"),
    ("header", "headers"), ("csp", "headers"), ("hsts", "headers"),
    ("cors", "headers"), ("tls", "transport"), ("unencrypted", "transport"),
    ("csrf", "csrf"), ("injection", "injection"),
    ("information", "info"), ("disclosure", "info"),
)


def _category_for(name: str, default: str) -> str:
    low = (name or "").lower()
    for kw, cat in _CATEGORY_KEYWORDS:
        if kw in low:
            return cat
    return default


def _evidence_for(f: dict) -> str:
    parts = []
    ev = (f.get("evidence") or "").strip()
    if ev:
        parts.append(ev)
    reqs = f.get("requests") or []
    if reqs and isinstance(reqs, list) and isinstance(reqs[0], dict):
        rq = (reqs[0].get("request") or "").strip()
        if rq:
            parts.append(rq)
    cvss = f.get("cvss_vector")
    if cvss:
        parts.append(f"CVSS: {cvss}")
    return ("\n".join(parts))[:600]


def _normalise_finding(f: dict, default_category: str) -> dict:
    definition = f.get("definition") or {}
    name = definition.get("name") or "Finding"
    param = f.get("parameter") or ""
    title = f"{name} in '{param}'" if param else name
    return {
        "severity": _norm_severity(f.get("severity"), f.get("cvss_score")),
        "title": title,
        "url": f.get("url") or f.get("path") or "",
        "evidence": _evidence_for(f),
        "cwe": definition.get("cwe") or "",
        "category": _category_for(name, default_category),
    }


_REGION_BASES = {
    "eu": "https://api.probely.com",
    "us": "https://api.us.probely.com",
    "au": "https://api.au.probely.com",
}
_DEFAULT_BASE = "https://api.probely.com"


def _resolve_api_base(cfg) -> str:
    base = (getattr(cfg, "probely_api_base", "") or "").strip()
    region = (getattr(cfg, "probely_region", "") or "").strip().lower()
    if base and base.rstrip("/") != _DEFAULT_BASE:
        return base
    if region in _REGION_BASES:
        return _REGION_BASES[region]
    return base or _DEFAULT_BASE


def _app_base(cfg) -> str:
    region = (getattr(cfg, "probely_region", "") or "").strip().lower()
    if region in ("us", "au"):
        return f"https://plus.{region}.probely.app"
    base = (getattr(cfg, "probely_api_base", "") or "").lower()
    if ".us.probely.com" in base:
        return "https://plus.us.probely.app"
    if ".au.probely.com" in base:
        return "https://plus.au.probely.app"
    return "https://plus.probely.app"


def _host_looks_non_public(url: str) -> bool:
    """Heuristic: True if the target host is almost certainly NOT reachable from
    Probely's cloud (private/loopback/link-local/.internal/.local or unresolvable),
    so the user would need a Scanning Agent. Best-effort and conservative."""
    import ipaddress
    import socket
    try:
        host = (urlparse(url).hostname or "").strip().lower()
    except Exception:
        return False
    if not host:
        return False
    if host in ("localhost",) or host.endswith((".local", ".internal", ".lan", ".test", ".localhost")):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = {i[4][0] for i in infos}
        if not addrs:
            return True
        for a in addrs:
            try:
                ip = ipaddress.ip_address(a)
                if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
                    return False
            except ValueError:
                return False
        return True
    except Exception:
        return True


class ProbelyError(Exception):
    """Raised for non-retryable API errors (auth, validation, not found)."""
    def __init__(self, message: str, *, status: int = 0, is_auth: bool = False):
        super().__init__(message)
        self.status = status
        self.is_auth = is_auth


def _truthy_env(name: str) -> bool:
    return (os.environ.get(name, "") or "").strip().lower() in ("1", "true", "yes", "on")


def _find_corporate_ca() -> Optional[str]:
    """Locate a corporate CA bundle that IT/MDM may already have configured, so
    we can trust a TLS-inspecting proxy *properly* instead of disabling checks.
    The first existing, non-empty file wins. ``PROBELY_CA_BUNDLE`` is checked
    first so this scanner can be pointed at a specific .pem without touching the
    shared env vars used by Node/curl/requests."""
    for var in ("PROBELY_CA_BUNDLE", "SNYK_CA_BUNDLE", "REQUESTS_CA_BUNDLE",
                "SSL_CERT_FILE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
        p = os.environ.get(var)
        try:
            if p and Path(p).is_file() and Path(p).stat().st_size > 0:
                return p
        except OSError:
            continue
    return None


def _build_probely_ssl_context(log: Callable[[str], None]) -> ssl.SSLContext:
    """TLS context for every Probely API call, hardened for corporate networks
    that run a TLS-inspecting proxy (common at banks). Two real-world problems
    are handled while keeping chain-building and hostname verification ON:

    1. The proxy re-signs traffic with a private corporate CA the default trust
       store doesn't know. We load it from the usual env vars (or point
       PROBELY_CA_BUNDLE at the exported .pem); on Windows we also fall back to
       exporting the machine cert store (where GPO usually installs it).

    2. Many corporate/appliance CAs set the basicConstraints extension but do
       NOT mark it *critical*. When Python is built against an OpenSSL that runs
       X.509-strict checks, the whole chain is then rejected with:
           "Basic Constraints of CA cert not marked critical"
       even though the CA is otherwise trusted. We clear ONLY that strict flag,
       so a trusted-but-pedantically-malformed CA is accepted.

    As an explicit, logged, opt-in last resort, setting PROBELY_INSECURE_TLS=1
    disables verification entirely (off by default)."""
    ca = _find_corporate_ca()
    if not ca and os.name == "nt":
        # Windows: the corporate root is usually only in the machine cert store.
        try:
            from static_scanner import _export_windows_ca_bundle  # lazy, optional
            ca = _export_windows_ca_bundle(log)
        except Exception:
            ca = None
    try:
        ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        if ca:
            log(f"[snyk-aw] using corporate CA bundle for TLS: {ca}")
    except Exception as e:
        log(f"[snyk-aw] could not load CA bundle {ca!r} ({e!r}); "
            f"falling back to the system trust store")
        ctx = ssl.create_default_context()

    # Relax ONLY the pedantic RFC-5280 strict checks (e.g. basicConstraints not
    # marked critical) that break TLS-inspection CAs. Chain + hostname stay ON.
    strict = getattr(ssl, "VERIFY_X509_STRICT", 0)
    if strict and (ctx.verify_flags & strict):
        ctx.verify_flags &= ~strict
        log("[snyk-aw] cleared X.509-strict verification flag (allows a trusted "
            "corporate CA whose basicConstraints isn't marked critical).")

    if _truthy_env("PROBELY_INSECURE_TLS"):
        log("[snyk-aw] WARNING: PROBELY_INSECURE_TLS=1 — TLS certificate "
            "verification is DISABLED for Probely API calls. Use only as a "
            "temporary workaround on a trusted network.")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _is_tls_verify_error(exc: BaseException) -> bool:
    """True if a urllib error was caused by TLS certificate verification."""
    reason = getattr(exc, "reason", exc)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return True
    return "CERTIFICATE_VERIFY_FAILED" in repr(exc)


def _tls_error_help(exc: BaseException, base: str) -> str:
    return (
        f"No se pudo verificar el certificado TLS de {base}. Tu red corporativa "
        "intercepta el tráfico HTTPS y presenta un certificado emitido por una CA "
        "interna. Soluciones, en orden:\n"
        "  1) Exporta la CA raíz de tu empresa a un archivo .pem y apunta la "
        "variable de entorno PROBELY_CA_BUNDLE a ese archivo, luego reinicia la app.\n"
        "  2) Si el detalle menciona «Basic Constraints of CA cert not marked "
        "critical», la app ya relaja esa comprobación automáticamente; reinstálala/"
        "reiníciala para tomar el cambio.\n"
        "  3) Último recurso temporal, solo en una red de confianza: define "
        "PROBELY_INSECURE_TLS=1 antes de abrir la app.\n"
        f"Detalle técnico: {exc!r}"
    )


# Default User-Agent for Probely API calls. urllib's built-in
# "Python-urllib/3.x" is widely blocked by WAFs / Cloudflare's Browser
# Integrity Check (which is exactly what produces the "Error 1010: Access
# denied … based on your browser's signature" 403). api.probely.com itself
# accepts non-browser clients (its own docs call it with curl), so an honest,
# non-urllib UA is enough. Override with PROBELY_USER_AGENT if a stricter
# corporate WAF demands a full browser UA.
_DEFAULT_UA = "BBScanner/1.0 (Snyk API & Web / Probely API client)"


def _resolve_user_agent() -> str:
    return (os.environ.get("PROBELY_USER_AGENT") or "").strip() or _DEFAULT_UA


def _looks_like_cloudflare_block(body: str) -> bool:
    """True if a 403 body is actually a Cloudflare WAF/Browser-Integrity block
    (Error 1010) rather than a Probely auth/permission denial."""
    low = (body or "").lower().replace(" ", "")
    return ('"error_code":1010' in low or "error1010" in low
            or "browser'ssignature" in low or "browsersignature" in low
            or ("cloudflare" in low and "accessdenied" in low))


def _cloudflare_block_help(body: str) -> str:
    return (
        "Bloqueo de Cloudflare (Error 1010, «Access denied»). NO es un problema "
        "del token ni de su rol: la petición se rechazó por la «firma» del cliente "
        "HTTP (su User-Agent / huella) ANTES de llegar a Probely. La prueba es que "
        "incluso /profile/ —que cualquier token puede leer— fue bloqueado.\n"
        "Qué hacer, en orden:\n"
        "  1) La app ahora envía un User-Agent propio en vez del de Python; "
        "reiníciala. Si tu WAF exige un navegador real, define la variable de "
        "entorno PROBELY_USER_AGENT con un User-Agent de Chrome/Edge.\n"
        "  2) Si persiste, casi siempre es el proxy/WAF corporativo o la IP de "
        "salida: pide a Ciberseguridad (slunam@bancobase.com) que permita el "
        "tráfico saliente hacia api.probely.com sin «Browser Integrity Check» / "
        "inspección de bots.\n"
        f"Detalle de Cloudflare: {body[:300]}"
    )


class _Probely:
    def __init__(self, token: str, base: str, log: Callable[[str], None],
                 scheme: str = "JWT"):
        if not token:
            raise ProbelyError(
                "No Snyk API & Web (Probely) credential available. Sign in to Snyk "
                "(SSO) so the scan can reuse that session before scanning.",
                is_auth=True)
        self._token = token
        self._scheme = (scheme or "JWT").strip() or "JWT"
        self._base = (base or "https://api.probely.com").rstrip("/")
        self._log = log
        self._ua = _resolve_user_agent()
        ctx = _build_probely_ssl_context(log)
        self._opener = build_opener(HTTPSHandler(context=ctx))

    def _url(self, path: str) -> str:
        return self._base + "/" + path.lstrip("/")

    def _request(self, method: str, path: str, *, body: Optional[bytes] = None,
                 content_type: Optional[str] = None, params: Optional[dict] = None,
                 expect=(200, 201), timeout: int = 60, retries: int = 4) -> Any:
        url = self._url(path)
        if params:
            url += ("&" if "?" in url else "?") + urlencode(params)
        headers = {
            "Authorization": f"{self._scheme} {self._token}",
            "Accept": "application/json",
            # Avoid urllib's default "Python-urllib/3.x" UA, which Cloudflare's
            # Browser Integrity Check blocks with Error 1010. Accept-Language is
            # one of the headers Cloudflare expects a real client to send.
            "User-Agent": self._ua,
            "Accept-Language": "en-US,en;q=0.9",
        }
        if content_type:
            headers["Content-Type"] = content_type
        last_exc: Optional[BaseException] = None
        for attempt in range(retries):
            req = Request(url, data=body, method=method, headers=headers)
            try:
                with self._opener.open(req, timeout=timeout) as r:
                    raw = r.read()
                    if r.status not in expect:
                        raise ProbelyError(f"{method} {path} → HTTP {r.status}",
                                           status=r.status)
                    return json.loads(raw) if raw else {}
            except HTTPError as e:
                code = e.code
                try:
                    detail = e.read(8000).decode("utf-8", "replace")
                except Exception:
                    detail = ""
                if code == 403 and _looks_like_cloudflare_block(detail):
                    # A Cloudflare WAF block (Error 1010) surfaces as HTTP 403 but
                    # is NOT an auth/role problem — report it as a network block.
                    raise ProbelyError(_cloudflare_block_help(detail),
                                       status=code, is_auth=False)
                if code in (401, 403):
                    raise ProbelyError(
                        f"Authentication/permission error (HTTP {code}). Check the "
                        f"API token and its role. {detail[:300]}",
                        status=code, is_auth=True)
                if code == 429 or 500 <= code < 600:
                    wait = _retry_after(e) or (2 ** attempt)
                    self._log(f"[snyk-aw] HTTP {code} on {method} {path}; "
                              f"retry in {wait:.0f}s")
                    last_exc = ProbelyError(f"HTTP {code}: {detail[:200]}", status=code)
                    time.sleep(min(wait, 30))
                    continue
                raise ProbelyError(f"{method} {path} → HTTP {code}: {detail[:300]}",
                                   status=code)
            except (URLError, TimeoutError) as e:
                if _is_tls_verify_error(e):
                    # Retrying a cert-verify failure never succeeds — fail fast
                    # with actionable guidance instead of N pointless attempts.
                    raise ProbelyError(_tls_error_help(e, self._base), is_auth=False)
                last_exc = e
                self._log(f"[snyk-aw] network error on {method} {path}: {e!r} "
                          f"(attempt {attempt + 1}/{retries})")
                time.sleep(min(2 ** attempt, 30))
            except json.JSONDecodeError as e:
                raise ProbelyError(f"Malformed JSON from {method} {path}: {e!r}")
        raise ProbelyError(f"{method} {path} failed after {retries} attempts: {last_exc!r}")

    def _get(self, path, **kw):  return self._request("GET", path, **kw)
    def _post(self, path, **kw): return self._request("POST", path, **kw)
    def _patch(self, path, **kw): return self._request("PATCH", path, **kw)
    def _delete(self, path, **kw):
        kw.setdefault("expect", (200, 202, 204))
        return self._request("DELETE", path, **kw)

    def whoami(self) -> dict:
        return self._get("/profile/")

    def find_target_by_url(self, url: str, ttype: Optional[str]) -> Optional[dict]:
        """Best-effort: page through targets and match site.url (and type)."""
        want = url.rstrip("/")
        page = 1
        while page <= 50:
            data = self._get("/targets/", params={"page": page})
            results = data.get("results") if isinstance(data, dict) else None
            if not results:
                break
            for t in results:
                site = t.get("site") or {}
                if (site.get("url") or "").rstrip("/") == want:
                    if ttype is None or (t.get("type") or "single") == ttype:
                        return t
            if data.get("page_total") and page >= data["page_total"]:
                break
            page += 1
        return None

    def create_web_target(self, name: str, url: str) -> dict:
        body = json.dumps({"site": {"name": name, "url": url}}).encode()
        return self._post("/targets/", body=body, content_type="application/json")

    def create_api_target(self, name: str, url: str, schema_type: str,
                          schema_url: str = "") -> dict:
        site: dict[str, Any] = {"name": name, "url": url,
                                "api_scan_settings": {"api_schema_type": schema_type}}
        if schema_url:
            site["api_scan_settings"]["api_schema_url"] = schema_url
        body = json.dumps({"site": site, "type": "api"}).encode()
        return self._post("/targets/", body=body, content_type="application/json")

    def upload_api_schema_file(self, target_id: str, file_path: str) -> dict:
        data, ctype = _multipart_file("file", file_path)
        return self._post(f"/targets/{target_id}/upload_api_schema_file/",
                          body=data, content_type=ctype)

    def add_login_sequence(self, target_id: str, name: str, content_json: str) -> dict:
        body = json.dumps({"name": name, "content": content_json,
                           "type": "login", "enabled": True}).encode()
        return self._post(f"/targets/{target_id}/sequences/", body=body,
                          content_type="application/json")

    def enable_sequence_auth(self, target_id: str) -> dict:
        body = json.dumps({"site": {"has_sequence_login": True,
                                    "has_form_login": False,
                                    "auth_enabled": True}}).encode()
        return self._patch(f"/targets/{target_id}/", body=body,
                           content_type="application/json")

    def configure_form_login(self, target_id: str, *, form_login_url: str,
                             fields: list[dict], check_pattern: str = "") -> dict:
        """Configure FORM-based authentication on the target.

        Probely logs in by filling a login form: it needs the login page URL and a
        list of {"name": <field id/name/CSS selector>, "value": <value>} pairs (the
        username/password fields, plus an optional {"name": "submit_button",
        "value": <CSS selector>} when the submit control is outside the <form>).
        ``check_pattern`` is the text/regex that confirms a successful login
        (site.form_login_check_pattern, max 255 chars). Enabling form login also
        disables sequence login — the two are mutually exclusive in Probely."""
        site: dict[str, Any] = {
            "has_form_login": True,
            "has_sequence_login": False,
            "auth_enabled": True,
            "form_login_url": form_login_url,
            "form_login": fields,
        }
        site["form_login_check_pattern"] = (check_pattern or "")[:255]
        body = json.dumps({"site": site}).encode()
        return self._patch(f"/targets/{target_id}/", body=body,
                           content_type="application/json")

    def set_blacklist(self, target_id: str, urls: list[str]) -> dict:
        """Replace the target's blacklist (URLs the crawler must never visit).
        Blacklist entries are absolute URLs; wildcards (*) are allowed and the
        blacklist takes precedence over the whitelist."""
        body = json.dumps({"site": {"blacklist": urls}}).encode()
        return self._patch(f"/targets/{target_id}/", body=body,
                           content_type="application/json")

    def list_logout_detectors(self, target_id: str) -> dict:
        return self._get(f"/targets/{target_id}/logout/")

    def create_logout_detector(self, target_id: str, value: str,
                               type_: str = "text") -> dict:
        body = json.dumps({"type": type_, "value": value}).encode()
        return self._post(f"/targets/{target_id}/logout/", body=body,
                          content_type="application/json")

    def update_logout_detector(self, target_id: str, detector_id: str,
                               type_: str, value: str) -> dict:
        """Update an existing logout detector. The CREATE endpoint only accepts
        text|url|sel; code|body|header types can only be set via this UPDATE.
        So we create as a placeholder type and then PATCH it to the real one."""
        body = json.dumps({"type": type_, "value": value}).encode()
        return self._patch(f"/targets/{target_id}/logout/{detector_id}/",
                           body=body, content_type="application/json")

    def enable_logout_detection(self, target_id: str, check_session_url: str,
                                condition: str = "any") -> dict:
        body = json.dumps({"site": {"check_session_url": check_session_url,
                                    "logout_detection_enabled": True,
                                    "logout_condition": condition}}).encode()
        return self._patch(f"/targets/{target_id}/", body=body,
                           content_type="application/json")

    def set_basic_auth(self, target_id: str, *, username: str, password: str) -> dict:
        """Configure Probely's NATIVE HTTP Basic authentication on the target
        (site.has_basic_auth / site.basic_auth), instead of synthesising an
        Authorization: Basic header. Cleaner, shows correctly in the Probely UI,
        and is handled by the scanner as a real auth method."""
        site: dict[str, Any] = {
            "has_basic_auth": True,
            "auth_enabled": True,
            "basic_auth": {"username": username, "password": password},
        }
        body = json.dumps({"site": site}).encode()
        return self._patch(f"/targets/{target_id}/", body=body,
                           content_type="application/json")

    def list_scan_profiles(self, target_type: str = "", *,
                           verified: Optional[bool] = None) -> list[dict]:
        """List built-in + custom scan profiles. ``target_type`` is "web"/"api"
        (Probely uses "web" for single web targets). Returns the raw result list
        with id/name/builtin fields. Used to populate the profile dropdown so the
        user only ever picks a real, existing profile id."""
        params: dict[str, Any] = {}
        if target_type:
            params["type"] = target_type
        if verified is not None:
            params["verified"] = "true" if verified else "false"
        profiles: list[dict] = []
        page = 1
        while page <= 20:
            params["page"] = page
            data = self._get("/scan-profiles/", params=params)
            for p in (data.get("results") or []):
                profiles.append(p)
            if not data.get("page_total") or page >= data["page_total"]:
                break
            page += 1
        return profiles

    def set_auth_credentials(self, target_id: str, *, cookies=None, headers=None,
                             auth_enabled: bool = True) -> dict:
        """Register static auth cookies/headers on the target. Marking them as
        authentication credentials (and allow_testing=false) both authenticates
        the cloud scan AND stops the scanner from fuzzing the session token, which
        is a common cause of self-inflicted logouts."""
        site: dict[str, Any] = {"auth_enabled": auth_enabled}
        if cookies is not None:
            site["cookies"] = cookies
        if headers is not None:
            site["headers"] = headers
        body = json.dumps({"site": site}).encode()
        return self._patch(f"/targets/{target_id}/", body=body,
                           content_type="application/json")

    def scan_now(self, target_id: str, *, scan_profile: str = "",
                 reduced_scopes: Optional[list] = None,
                 ignore_blackout: bool = False) -> dict:
        payload: dict[str, Any] = {}
        if scan_profile:
            payload["scan_profile"] = scan_profile
        if reduced_scopes:
            payload["reduced_scopes"] = reduced_scopes
        if ignore_blackout:
            payload["ignore_blackout"] = True
        body = json.dumps(payload).encode() if payload else b"{}"
        return self._post(f"/targets/{target_id}/scan_now/", body=body,
                          content_type="application/json")

    def get_scan(self, target_id: str, scan_id: str) -> dict:
        return self._get(f"/targets/{target_id}/scans/{scan_id}")

    def cancel_scan(self, target_id: str, scan_id: str) -> dict:
        return self._post(f"/targets/{target_id}/scans/{scan_id}/cancel/",
                          body=b"{}", content_type="application/json",
                          expect=(200, 201, 202))

    def list_targets(self) -> list[dict]:
        """Page through every target in the account (the orchestrator pool)."""
        out: list[dict] = []
        page = 1
        while page <= 50:
            data = self._get("/targets/", params={"page": page})
            results = data.get("results") if isinstance(data, dict) else None
            if not results:
                break
            out.extend(results)
            if not data.get("page_total") or page >= data["page_total"]:
                break
            page += 1
        return out

    def delete_target(self, target_id: str) -> dict:
        """DELETE a target, freeing its slot in the pool."""
        return self._delete(f"/targets/{target_id}/")

    def list_scans_for_target(self, target_id: str) -> list[dict]:
        """All scans for a target. Primary endpoint is the account-wide
        ``GET /scans/?f_target=<id>``; falls back to the per-target
        ``GET /targets/<id>/scans/`` if the filtered list isn't available."""
        out: list[dict] = []
        try:
            page = 1
            while page <= 50:
                data = self._get("/scans/", params={"f_target": target_id, "page": page})
                results = data.get("results") if isinstance(data, dict) else None
                if results is None:
                    raise ProbelyError("no results key on /scans/")
                out.extend(results)
                if not data.get("page_total") or page >= data["page_total"]:
                    break
                page += 1
            return out
        except ProbelyError:
            out = []
            page = 1
            while page <= 50:
                data = self._get(f"/targets/{target_id}/scans/", params={"page": page})
                results = data.get("results") if isinstance(data, dict) else None
                if not results:
                    break
                out.extend(results)
                if not data.get("page_total") or page >= data["page_total"]:
                    break
                page += 1
            return out


    def iter_findings(self, target_id: str, *, state: str = "notfixed"):
        page = 1
        while page <= 200:
            data = self._get(f"/targets/{target_id}/findings/",
                             params={"state": state, "page": page})
            for f in (data.get("results") or []):
                yield f
            if not data.get("page_total") or page >= data["page_total"]:
                break
            page += 1

    def configure_2fa(self, target_id: str, *, secret: str, otp_field: str = "",
                      otp_submit: str = "", algorithm: str = "SHA1",
                      digits: int = 6) -> dict:
        """Enable TOTP-based 2FA on the target. Requires a login method already
        set. otp_field/otp_submit are CSS selectors of the 2FA form (form login)."""
        site: dict[str, Any] = {"has_otp": True, "otp_secret": secret}
        if otp_field:
            site["otp_field"] = otp_field
        if otp_submit:
            site["otp_submit"] = otp_submit
        if algorithm:
            site["otp_algorithm"] = algorithm
        if digits:
            site["otp_digits"] = int(digits)
        body = json.dumps({"site": site}).encode()
        return self._patch(f"/targets/{target_id}/", body=body,
                           content_type="application/json")

    def list_extra_hosts(self, target_id: str) -> dict:
        return self._get(f"/targets/{target_id}/extra_hosts/")

    def add_extra_host(self, target_id: str, url: str) -> dict:
        body = json.dumps({"url": url}).encode()
        return self._post(f"/targets/{target_id}/extra_hosts/", body=body,
                          content_type="application/json")

    def check_api_login(self, target_id: str) -> dict:
        """Ask Probely to test the configured API login by performing a login
        request. Endpoint is best-effort; returns {} if unsupported."""
        return self._post(f"/targets/{target_id}/check_api_login/", body=b"{}",
                          content_type="application/json",
                          expect=(200, 201, 202))

    def configure_api_login(self, target_id: str, *, login_url: str, payload: str,
                            media_type: str, token_field: str, token_param: str,
                            token_prefix: str, place: str = "header") -> dict:
        """Configure API Target Authentication via a login ENDPOINT (token
        retrieval): POST ``payload`` to ``login_url``, read the token from
        ``token_field`` of the JSON response, then send it on every request in
        the ``token_param`` header/cookie with an optional ``token_prefix``.

        Best-effort: field names follow Probely's API Target Authentication
        module but may vary by account/version, so this is sent in its OWN PATCH
        (isolated from the rest of the target setup) and the caller logs + keeps
        going if Probely rejects it. Validate against your account's API
        reference if check_api_login fails."""
        site: dict[str, Any] = {
            "api_login_url": login_url,
            "api_login_payload": payload,
            "api_login_media_type": media_type or "application/json",
            "api_login_token_field": token_field,
            "api_login_token_param": token_param or "Authorization",
            "api_login_token_prefix": token_prefix or "",
            "api_login_token_place": place or "header",
            "auth_enabled": True,
        }
        body = json.dumps({"site": site}).encode()
        return self._patch(f"/targets/{target_id}/", body=body,
                           content_type="application/json")

    def download_report(self, target_id: str, scan_id: str, template: str,
                        timeout: int = 120) -> bytes:
        """Download a scan report as PDF for the given compliance template."""
        url = self._url(f"/targets/{target_id}/scans/{scan_id}/report/")
        url += ("&" if "?" in url else "?") + urlencode({"report_type": template})
        headers = {"Authorization": f"{self._scheme} {self._token}",
                   "Accept": "application/pdf"}
        req = Request(url, method="GET", headers=headers)
        with self._opener.open(req, timeout=timeout) as r:
            if r.status not in (200, 201):
                raise ProbelyError(f"report download → HTTP {r.status}", status=r.status)
            return r.read()


def _retry_after(exc: HTTPError) -> float:
    try:
        v = exc.headers.get("Retry-After")
        return float(v) if v else 0.0
    except Exception:
        return 0.0


def _multipart_file(field_name: str, file_path: str) -> tuple[bytes, str]:
    """Build a minimal multipart/form-data body for a single file upload."""
    p = Path(file_path)
    payload = p.read_bytes()
    filename = p.name
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    boundary = "----snykaw" + uuid.uuid4().hex
    pre = (f"--{boundary}\r\n"
           f'Content-Disposition: form-data; name="{field_name}"; '
           f'filename="{filename}"\r\n'
           f"Content-Type: {ctype}\r\n\r\n").encode()
    post = f"\r\n--{boundary}--\r\n".encode()
    return pre + payload + post, f"multipart/form-data; boundary={boundary}"


def macro_to_probely_sequence(macro: list) -> str:
    """Convert the local Selenium macro (list of recorded events) into a JSON
    string suitable for a Probely login sequence.

    IMPORTANT — schema caveat: Probely's authoritative login-sequence JSON is the
    one its Sequence Recorder browser plugin exports. The exact internal schema
    is not part of the public REST docs, so this converter emits a Selenium-IDE
    style command list (the common interchange shape) as a BEST-EFFORT bridge.
    Validate it against one real Probely export before relying on it; for
    guaranteed compatibility, record once with Probely's plugin and pass the file
    via ``cfg.probely_login_sequence_path`` (that path is used verbatim).
    """
    commands: list = []

    start_url = ""
    for ev in (macro or []):
        if isinstance(ev, dict) and (ev.get("url") or "").strip():
            start_url = ev["url"].strip()
            break
    if start_url:
        commands.append({"command": "open", "target": start_url, "value": ""})

    for ev in (macro or []):
        if not isinstance(ev, dict):
            continue
        kind = ev.get("kind") or ev.get("type")
        sel  = ev.get("selector") or ev.get("sel") or ""
        url  = ev.get("url") or ""
        val  = ev.get("value")

        if kind in ("navigate", "open"):
            if url and (not commands or commands[-1].get("target") != url):
                commands.append({"command": "open", "target": url, "value": ""})
        elif kind in ("field", "input", "change") and sel:
            tgt = _css(sel)
            v = "" if val is None else str(val)
            if (commands and commands[-1].get("command") == "type"
                    and commands[-1].get("target") == tgt):
                commands[-1]["value"] = v
            else:
                commands.append({"command": "type", "target": tgt, "value": v})
        elif kind == "click" and sel:
            commands.append({"command": "click", "target": _css(sel), "value": ""})
        elif kind == "submit":
            btn  = ev.get("button") or sel
            form = ev.get("form") or sel
            if btn:
                tgt = _css(btn)
                if not (commands and commands[-1].get("command") == "click"
                        and commands[-1].get("target") == tgt):
                    commands.append({"command": "click", "target": tgt, "value": ""})
            elif form:
                commands.append({"command": "submit", "target": _css(form), "value": ""})
        elif kind in ("enter", "keydown"):
            tgt = sel or ev.get("form") or ""
            if tgt and not (commands and commands[-1].get("command")
                            in ("click", "submit", "sendKeys")):
                commands.append({"command": "sendKeys", "target": _css(tgt),
                                 "value": "${KEY_ENTER}"})
    seq = {"version": "selenium-ide-compatible", "commands": commands}
    return json.dumps(seq)


def _css(sel: str) -> str:
    return sel if sel.startswith(("css=", "id=", "name=", "xpath=")) else f"css={sel}"


def _resolve_login_sequence(cfg, log) -> Optional[tuple[str, str]]:
    """Return (name, content_json) for the login sequence, or None.

    Priority: an explicit Probely-recorded file (authoritative) over a converted
    local Selenium macro (best-effort)."""
    path = getattr(cfg, "probely_login_sequence_path", "") or ""
    if path:
        p = Path(path)
        if p.exists():
            log(f"[snyk-aw] using Probely login sequence file: {p.name}")
            return (p.stem or "login sequence", p.read_text(encoding="utf-8"))
        log(f"[snyk-aw] login sequence file not found: {path}")
    macro_raw = getattr(cfg, "selenium_macro", "") or ""
    if macro_raw:
        try:
            macro = json.loads(macro_raw) if isinstance(macro_raw, str) else macro_raw
        except Exception:
            macro = None
        if macro:
            log("[snyk-aw] converting recorded Selenium macro → Probely sequence "
                "(best-effort; validate against a real Probely export).")
            return ("converted login sequence", macro_to_probely_sequence(macro))
    return None


def _resolve_form_login(cfg, base_url: str, log) -> Optional[tuple[str, list[dict], str]]:
    """Build a Probely FORM-login configuration from the config, or return None.

    Returns ``(form_login_url, fields, check_pattern)`` where ``fields`` is a list
    of ``{"name", "value"}`` pairs. Two ways to source the field pairs (in order):

      1. ``login_data`` — a urlencoded form body (``uid=admin&passwd=secret``). The
         keys ARE the form field names, which is exactly what Probely's form_login
         wants, so this maps 1:1. This is the classic ``auth_type == "form"`` path.
      2. The Selenium selector/value fields (``selenium_user_selector`` +
         ``selenium_user_value`` and the password equivalents) — Probely accepts an
         id/name/CSS selector as the field "name".

    An explicit/derived submit-button selector is appended as a ``submit_button``
    field when present. ``check_pattern`` falls back to ``login_success_text``."""
    mode = (getattr(cfg, "probely_form_login", "auto") or "auto").strip().lower()
    if mode == "off":
        return None
    auth = (getattr(cfg, "auth_type", "none") or "none").strip().lower()

    fields: list[dict] = []
    login_data = (getattr(cfg, "login_data", "") or "").strip()
    if login_data:
        for k, val in parse_qsl(login_data, keep_blank_values=True):
            if k:
                fields.append({"name": k, "value": val})
    else:
        user_sel = (getattr(cfg, "selenium_user_selector", "") or "").strip()
        user_val = (getattr(cfg, "selenium_user_value", "") or
                    getattr(cfg, "username", "") or "")
        pass_sel = (getattr(cfg, "selenium_pass_selector", "") or "").strip()
        pass_val = (getattr(cfg, "selenium_pass_value", "") or
                    getattr(cfg, "password", "") or "")
        if user_sel and user_val:
            fields.append({"name": user_sel, "value": user_val})
        if pass_sel and pass_val:
            fields.append({"name": pass_sel, "value": pass_val})

    cred_fields = [f for f in fields if f["name"] != "submit_button"]
    submit = (getattr(cfg, "probely_form_submit_selector", "") or
              getattr(cfg, "selenium_submit_selector", "") or "").strip()
    if submit:
        fields.append({"name": "submit_button", "value": submit})

    explicit = (mode == "on") or (auth == "form")
    if not cred_fields:
        if explicit:
            log("[snyk-aw] form login requested but no username/password field "
                "pairs were found (set login_data, or the user/password selectors "
                "and values). Skipping form login.")
        return None

    form_url = (getattr(cfg, "login_url", "") or
                getattr(cfg, "selenium_login_url", "") or base_url or "").strip()
    check = (getattr(cfg, "probely_form_login_check_pattern", "") or
             getattr(cfg, "login_success_text", "") or "").strip()
    return (form_url, fields, check[:255])


def _decide_login_method(cfg, url: str, log
                         ) -> tuple[Optional[str], Optional[tuple], Optional[tuple]]:
    """Pick the crawler authentication method. Form login and sequence login are
    mutually exclusive in Probely, so we choose exactly one. Precedence:

      1. An authoritative Probely sequence FILE (probely_login_sequence_path).
      2. Form login when forced (probely_form_login == "on") or auth_type == "form".
      3. A converted Selenium macro → best-effort sequence.
      4. Form login in "auto" mode when user/pass selectors happen to be present.

    Returns ``(method, seq, form)`` where method is "sequence" | "form" | None,
    ``seq`` is ``(name, content_json)`` and ``form`` is
    ``(form_login_url, fields, check_pattern)``."""
    seq = _resolve_login_sequence(cfg, log)
    form = _resolve_form_login(cfg, url, log)
    seq_from_file = bool((getattr(cfg, "probely_login_sequence_path", "") or "").strip())
    form_mode = (getattr(cfg, "probely_form_login", "auto") or "auto").strip().lower()
    auth = (getattr(cfg, "auth_type", "none") or "none").strip().lower()
    form_forced = form is not None and (form_mode == "on" or auth == "form")

    if seq and seq_from_file:
        return "sequence", seq, form
    if form_forced:
        return "form", seq, form
    if seq:
        return "sequence", seq, form
    if form:
        return "form", seq, form
    return None, seq, form


_LOGOUT_PATH_RE = re.compile(
    r"(?i)(log-?out|log-?off|sign-?out|signout|cerrar[-_]?sesi|salir|"
    r"desconect|deslog|/exit\b|/api/logout)")


def _abs_url(u: str, base_url: str) -> str:
    u = (u or "").strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = urljoin(base_url.rstrip("/") + "/", u.lstrip("/"))
    return u


def _would_exclude_whole_site(u: str, base_url: str) -> bool:
    """True if blacklisting u would knock out the start URL / the whole site."""
    try:
        p, b = urlparse(u), urlparse(base_url)
    except Exception:
        return False
    path = (p.path or "").rstrip("/")
    base_path = (b.path or "").rstrip("/")
    if path in ("", "/"):
        return True
    if p.netloc == b.netloc and path == base_path:
        return True
    return False


def logout_macro_to_blacklist(cfg, base_url: str, log) -> list[str]:
    """Derive SAFE absolute, wildcarded blacklist URLs from the recorded logout
    macro, the logout regex, and any explicit user list. Never returns an entry
    that would exclude the site root or the target's start URL."""
    out: list[str] = []
    coincided = False

    def _add(u: str, *, require_logout_pathy: bool):
        nonlocal coincided
        u = _abs_url(u, base_url)
        if not u:
            return
        if _would_exclude_whole_site(u, base_url):
            coincided = True
            return
        if require_logout_pathy and not _LOGOUT_PATH_RE.search(u):
            return
        if "*" not in u:
            u = u.rstrip("/") + "*"
        if u not in out:
            out.append(u)

    macro_raw = getattr(cfg, "selenium_logout_macro", "") or ""
    if macro_raw:
        try:
            macro = json.loads(macro_raw) if isinstance(macro_raw, str) else macro_raw
        except Exception:
            macro = []
        for ev in (macro or []):
            if isinstance(ev, dict) and ev.get("url"):
                _add(ev["url"], require_logout_pathy=True)

    for chunk in _re_split(getattr(cfg, "probely_blacklist", "") or ""):
        _add(chunk, require_logout_pathy=False)

    if getattr(cfg, "logout_url_re", "") or getattr(cfg, "exclude_re", ""):
        b = urlparse(base_url)
        root = f"{b.scheme or 'https'}://{b.netloc}"
        for path in ("/logout", "/logoff", "/log-off", "/signout", "/sign-out",
                     "/cerrar-sesion", "/cerrarsesion", "/cerrar_sesion",
                     "/salir", "/desconectar", "/desconexion", "/api/logout"):
            _add(root + path, require_logout_pathy=False)

    if coincided:
        log("[snyk-aw] WARNING: a logout URL resolves to the site root / the "
            "target start URL, so it cannot be blacklisted without excluding the "
            "whole site. Skipped it. Relying on the login sequence to re-login if "
            "the session drops; for robustness configure a Probely logout detector "
            "(session-check pattern) instead of URL exclusion.")
    if out:
        log(f"[snyk-aw] logout/exclusion blacklist ({len(out)} URL globs): "
            + ", ".join(out[:8]) + (" …" if len(out) > 8 else ""))
    elif not coincided:
        log("[snyk-aw] no logout URLs to blacklist.")
    return out


def _re_split(s: str) -> list[str]:
    return [p.strip() for p in re.split(r"[\n,]+", s) if p.strip()]


_DEFAULT_LOGOUT_MARKERS = (
    "Iniciar sesión", "Iniciar sesion", "Su sesión ha expirado",
    "Su sesión ha caducado", "Sesión expirada", "Sesión caducada",
    "Vuelva a iniciar sesión", "Usuario y contraseña", "Acceso denegado",
    "Sign in", "Log in", "Your session has expired",
    "Session expired", "Please log in again",
)


def resolve_logout_markers(cfg) -> list[str]:
    custom = _re_split(getattr(cfg, "probely_logout_markers", "") or "")
    return custom or list(_DEFAULT_LOGOUT_MARKERS)


_TERMINAL = {"completed", "completed_with_errors", "under_review",
             "canceled", "cancelled", "failed", "over"}


def _ensure_target(client: _Probely, cfg, *, url: str, is_api: bool,
                   log) -> dict:
    """Reuse or create a Probely target. Aborts (raises) if it can't be verified."""
    name = f"{'API' if is_api else 'Web'}: {urlparse(url).hostname or url}"

    tid = getattr(cfg, "probely_target_id", "") or ""
    target = None
    if tid:
        target = client._get(f"/targets/{tid}")
        log(f"[snyk-aw] reusing configured target {tid}")
    if target is None and getattr(cfg, "probely_reuse_by_url", True):
        target = client.find_target_by_url(url, "api" if is_api else None)
        if target:
            log(f"[snyk-aw] reusing existing target {target.get('id')} (matched URL)")
    if target is None:
        # ── Slot-pool orchestration ───────────────────────────────────────────
        # The account caps live targets (5 on the top plan). Before creating a
        # NEW target, make sure there's a free slot: if the pool is full, recycle
        # a target that has no active scan AND was not created within the cooldown
        # window. The whole "free a slot then create" runs under a per-account
        # lock so the concurrent DAST and API stages can't both grab the last slot.
        try:
            from probely_orchestrator import make_orchestrator, SlotUnavailable
        except Exception as _imp_err:
            make_orchestrator = None
            log(f"[snyk-aw] orchestrator unavailable ({_imp_err!r}); creating target "
                "without pool management.")
        orch = make_orchestrator(client, cfg, log) if make_orchestrator else None
        _ttype = "api" if is_api else "single"
        import contextlib as _contextlib
        _lock_cm = orch.account_lock() if orch else _contextlib.nullcontext()
        with _lock_cm:
            if orch is not None:
                try:
                    orch.ensure_capacity(
                        url, _ttype,
                        protect_ids=(getattr(cfg, "probely_target_id", "") or "",))
                except SlotUnavailable as e:
                    raise ProbelyError(str(e))
            if is_api:
                schema_src = (getattr(cfg, "spec_source", "") or "").strip()
                forced = (getattr(cfg, "probely_api_schema_type", "") or "").strip().lower()
                if forced in ("openapi", "postman", "graphql"):
                    schema_type = forced
                elif _looks_postman(schema_src):
                    schema_type = "postman"
                elif _looks_graphql(schema_src):
                    schema_type = "graphql"
                else:
                    schema_type = "openapi"
                schema_url = schema_src if schema_src.startswith(("http://", "https://")) else ""
                target = client.create_api_target(name, url, schema_type, schema_url)
                tid = target["id"]
                log(f"[snyk-aw] created API target {tid} (schema_type={schema_type})")
                if not schema_url and schema_src:
                    client.upload_api_schema_file(tid, schema_src)
                    log(f"[snyk-aw] uploaded API schema file: {Path(schema_src).name}")
            else:
                target = client.create_web_target(name, url)
                log(f"[snyk-aw] created web target {target['id']}")
            if orch is not None:
                try:
                    orch.register_created(target, url=url, ttype=_ttype)
                except Exception as e:
                    log(f"[snyk-aw] could not record target in pool ledger: {e!r}")

    site = target.get("site") or {}
    if not site.get("verified", False):
        token = site.get("verification_token", "")
        if getattr(cfg, "probely_require_verified", False):
            raise ProbelyError(
                "Target domain is NOT verified in Snyk API & Web. Probely will not "
                "scan it (unverified scans are treated as attacks). Verify the domain "
                f"first (verification token: {token}).")
        log("[snyk-aw] WARNING: target domain is NOT verified. Probely restricts "
            "unverified targets to LIGHTNING scans only — forcing the lightning "
            f"profile. Verify the domain to unlock full scans (token: {token}).")
        target["_force_lightning"] = True

    if not is_api and getattr(cfg, "probely_agent_warn", True):
        try:
            if _host_looks_non_public(url):
                log("[snyk-aw] WARNING: the target host looks non-public "
                    "(private/loopback/unresolvable). Probely's cloud scanner cannot "
                    "reach it without a Scanning Agent deployed in your network. "
                    "If you already configured an agent on this target, ignore this.")
        except Exception:
            pass

    method, seq, form = _decide_login_method(cfg, url, log)
    has_login = False
    if method == "sequence" and seq:
        name_, content_ = seq
        try:
            client.add_login_sequence(target["id"], name_, content_)
            client.enable_sequence_auth(target["id"])
            has_login = True
            log("[snyk-aw] login sequence attached and authentication enabled.")
        except ProbelyError as e:
            log(f"[snyk-aw] could not attach login sequence: {e} "
                "(scan will run unauthenticated).")
    elif method == "form" and form:
        form_url, fields, check = form
        try:
            client.configure_form_login(target["id"], form_login_url=form_url,
                                        fields=fields, check_pattern=check)
            has_login = True
            n_creds = len([f for f in fields if f["name"] != "submit_button"])
            log(f"[snyk-aw] form login configured at {form_url or '(target URL)'} "
                f"({n_creds} field(s); check_pattern="
                f"{'set' if check else 'none'}). Probely re-fills this form to "
                "authenticate the scan.")
        except ProbelyError as e:
            log(f"[snyk-aw] could not configure form login: {e} "
                "(scan will run unauthenticated).")

    if is_api and not has_login and getattr(cfg, "probely_api_login_url", "").strip():
        try:
            client.configure_api_login(
                target["id"],
                login_url=cfg.probely_api_login_url.strip(),
                payload=getattr(cfg, "probely_api_login_payload", "") or "",
                media_type=getattr(cfg, "probely_api_login_media_type", "application/json"),
                token_field=getattr(cfg, "probely_api_login_token_field", "") or "",
                token_param=getattr(cfg, "probely_api_login_token_param", "Authorization"),
                token_prefix=getattr(cfg, "probely_api_login_token_prefix", "") or "",
                place=getattr(cfg, "probely_api_login_place", "header"))
            has_login = True
            log("[snyk-aw] API login endpoint configured (token retrieval). "
                "Best-effort: if the login self-test fails, validate the api_login_* "
                "field names against your account's API reference.")
        except ProbelyError as e:
            log(f"[snyk-aw] could not configure API login endpoint: {e} "
                "(scan will run with whatever static auth is set).")

    if not has_login and getattr(cfg, "probely_protect_session", True):
        if _protect_session_credentials(client, cfg, target, log):
            has_login = True

    if getattr(cfg, "probely_2fa_enabled", False) and getattr(cfg, "probely_otp_secret", ""):
        if not has_login:
            log("[snyk-aw] 2FA requested but no login method is configured — "
                "skipped (2FA layers on top of form/sequence login).")
        else:
            try:
                client.configure_2fa(
                    target["id"], secret=cfg.probely_otp_secret,
                    otp_field=getattr(cfg, "probely_otp_field", "") or "",
                    otp_submit=getattr(cfg, "probely_otp_submit", "") or "",
                    algorithm=getattr(cfg, "probely_otp_algorithm", "SHA1") or "SHA1",
                    digits=int(getattr(cfg, "probely_otp_digits", 6) or 6))
                log("[snyk-aw] 2FA (TOTP) configured on the target.")
            except ProbelyError as e:
                log(f"[snyk-aw] could not configure 2FA: {e}")

    if not is_api:
        for host_url in _re_split(getattr(cfg, "probely_extra_hosts", "") or ""):
            hu = _abs_url(host_url, url)
            try:
                client.add_extra_host(target["id"], hu)
                log(f"[snyk-aw] extra host added to scope: {hu}")
            except ProbelyError as e:
                log(f"[snyk-aw] could not add extra host {hu}: {e}")

    if is_api and has_login and getattr(cfg, "probely_check_login", True):
        try:
            client.check_api_login(target["id"])
            log("[snyk-aw] API login configuration test requested.")
        except ProbelyError as e:
            log(f"[snyk-aw] API login test not available/failed: {e}")

    if not is_api:
        blacklist = logout_macro_to_blacklist(cfg, url, log)
        if blacklist:
            existing = (target.get("site") or {}).get("blacklist") or []
            merged = list(dict.fromkeys(list(existing) + blacklist))
            try:
                client.set_blacklist(target["id"], merged)
                log(f"[snyk-aw] blacklist set ({len(merged)} entries).")
            except ProbelyError as e:
                log(f"[snyk-aw] could not set blacklist: {e}")

        if getattr(cfg, "probely_logout_detection", True):
            if not has_login:
                log("[snyk-aw] logout detection requested but no login is "
                    "configured — skipped (nothing to re-login with).")
            else:
                _setup_logout_detection(client, cfg, target, url, log)
    return target


def _setup_logout_detection(client: _Probely, cfg, target: dict, url: str,
                            log) -> None:
    tid = target["id"]
    check_url = (getattr(cfg, "probely_check_session_url", "") or "").strip() or url
    condition = (getattr(cfg, "probely_logout_condition", "any") or "any").strip().lower()
    if condition not in ("any", "all"):
        condition = "any"

    detectors: list[tuple[str, str]] = [("text", mk) for mk in resolve_logout_markers(cfg)]
    if getattr(cfg, "probely_logout_url_detector", True):
        login_url = (getattr(cfg, "probely_login_url", "") or
                     getattr(cfg, "selenium_login_url", "") or
                     getattr(cfg, "login_url", "") or "").strip()
        if login_url:
            detectors.append(("url", login_url))
    if getattr(cfg, "probely_logout_code_detector", True):
        detectors.append(("code", "401"))
        detectors.append(("code", "403"))
    sel = (getattr(cfg, "probely_logout_selector", "") or "").strip()
    if sel:
        detectors.append(("sel", sel))
    for mk in _re_split(getattr(cfg, "probely_logout_body_markers", "") or ""):
        detectors.append(("body", mk))
    for mk in _re_split(getattr(cfg, "probely_logout_header_markers", "") or ""):
        detectors.append(("header", mk))

    try:
        existing = {(d.get("type"), d.get("value")) for d in
                    (client.list_logout_detectors(tid).get("results") or [])}
    except ProbelyError:
        existing = set()
    _CREATABLE_DET = {"text", "url", "sel"}
    by_type: dict[str, int] = {}
    for typ, val in detectors:
        if (typ, val) in existing:
            continue
        try:
            if typ in _CREATABLE_DET:
                client.create_logout_detector(tid, val, type_=typ)
            else:
                created = client.create_logout_detector(tid, val, type_="text")
                det_id = created.get("id")
                if det_id:
                    client.update_logout_detector(tid, det_id, typ, val)
                else:
                    raise ProbelyError("create returned no detector id")
            by_type[typ] = by_type.get(typ, 0) + 1
        except ProbelyError as e:
            log(f"[snyk-aw] could not add {typ} logout detector {val!r}: {e}")
    try:
        client.enable_logout_detection(tid, check_url, condition)
        summary = ", ".join(f"{n} {t}" for t, n in by_type.items()) or "0 new"
        log(f"[snyk-aw] logout detection ON (condition={condition}; added {summary}; "
            f"check_session_url={check_url}). If logged out, it re-logins automatically "
            "instead of scanning as anonymous.")
    except ProbelyError as e:
        log(f"[snyk-aw] could not enable logout detection: {e} "
            "(needs a login method + check_session_url defined).")


def _protect_session_credentials(client: _Probely, cfg, target: dict, log) -> bool:
    """Register the user's static auth credential (cookie/header/bearer/basic) on
    the Probely target with authentication=true and allow_testing=false. This both
    authenticates the cloud scan and prevents the scanner from fuzzing the session
    token (a frequent self-inflicted logout). Returns True if anything was set."""
    auth = (getattr(cfg, "auth_type", "none") or "none").lower()
    new_cookies: list[dict] = []
    new_headers: list[dict] = []
    if auth == "basic" and getattr(cfg, "username", ""):
        try:
            client.set_basic_auth(target["id"], username=cfg.username,
                                  password=getattr(cfg, "password", "") or "")
            log("[snyk-aw] native HTTP Basic authentication configured on the target.")
            return True
        except ProbelyError as e:
            log(f"[snyk-aw] could not set native basic auth ({e}); "
                "falling back to an Authorization header.")
            new_headers.append({
                "name": "Authorization",
                "value": "Basic " + base64.b64encode(
                    f"{cfg.username}:{getattr(cfg, 'password', '')}".encode()).decode(),
                "authentication": True, "allow_testing": False})
    if auth == "cookie" and getattr(cfg, "cookie", ""):
        for part in str(cfg.cookie).split(";"):
            if "=" in part:
                n, v = part.split("=", 1)
                if n.strip():
                    new_cookies.append({"name": n.strip(), "value": v.strip(),
                                        "authentication": True, "allow_testing": False})
    elif auth == "header" and getattr(cfg, "header_name", ""):
        new_headers.append({"name": cfg.header_name.strip(),
                            "value": getattr(cfg, "header_value", "") or "",
                            "authentication": True, "allow_testing": False})
    elif auth == "bearer" and getattr(cfg, "token", ""):
        new_headers.append({"name": "Authorization", "value": f"Bearer {cfg.token}",
                            "authentication": True, "allow_testing": False})
    if not new_cookies and not new_headers:
        return False

    site = target.get("site") or {}

    def _merge(existing, new):
        names = {e.get("name") for e in new}
        kept = [e for e in (existing or []) if e.get("name") not in names]
        return kept + new

    cookies = _merge(site.get("cookies"), new_cookies) if new_cookies else None
    headers = _merge(site.get("headers"), new_headers) if new_headers else None
    try:
        client.set_auth_credentials(target["id"], cookies=cookies, headers=headers)
        what = []
        if new_cookies:
            what.append(f"{len(new_cookies)} cookie(s)")
        if new_headers:
            what.append(f"{len(new_headers)} header(s)")
        log(f"[snyk-aw] static auth registered ({', '.join(what)}) as "
            "authentication + non-testable — the scanner won't fuzz the session "
            "token, so it can't log itself out that way.")
        return True
    except ProbelyError as e:
        log(f"[snyk-aw] could not register static auth credentials: {e}")
        return False


def _looks_postman(src: str) -> bool:
    if not src:
        return False
    if src.startswith(("http://", "https://")):
        return False
    try:
        data = json.loads(Path(src).read_text(encoding="utf-8", errors="replace"))
        return isinstance(data, dict) and "item" in data and "paths" not in data
    except Exception:
        return False


def _looks_graphql(src: str) -> bool:
    """Heuristic: a GraphQL SDL file (.graphql/.gql) or a saved introspection
    result. URLs are left to explicit override (a GraphQL endpoint URL is also a
    valid 'introspection' source for Probely)."""
    if not src:
        return False
    low = src.lower()
    if low.endswith((".graphql", ".gql", ".graphqls")):
        return True
    if src.startswith(("http://", "https://")):
        return False
    try:
        txt = Path(src).read_text(encoding="utf-8", errors="replace")
        tl = txt.lower()
        if "__schema" in txt and '"data"' in tl:
            return True
        return ("type query" in tl) or ("schema {" in tl and "query:" in tl)
    except Exception:
        return False


def _profile_for(cfg) -> str:
    """Pick the Probely scan profile. Explicit override wins; otherwise map the
    legacy passive/active toggle best-effort and leave default if unknown."""
    explicit = (getattr(cfg, "probely_scan_profile", "") or "").strip()
    if explicit:
        return explicit
    legacy = (getattr(cfg, "profile", "") or "").lower()
    if legacy == "active":
        return "full"
    return ""


def _drive_scan(client: _Probely, cfg, target: dict, *, out_name: str,
                default_category: str, log, cancel: threading.Event,
                progress: Optional[Callable[[int, int], None]],
                out_dir: Optional[Path] = None) -> dict:
    tid = target["id"]
    profile = _profile_for(cfg)
    if target.get("_force_lightning"):
        if profile and profile != "lightning":
            log(f"[snyk-aw] overriding profile '{profile}' → 'lightning' "
                "(target domain not verified).")
        profile = "lightning"
    reduced = []
    for u in _re_split(getattr(cfg, "probely_reduced_scopes", "") or ""):
        reduced.append({"url": u, "enabled": True})
    ignore_blackout = bool(getattr(cfg, "probely_ignore_blackout", False))
    scan = client.scan_now(tid, scan_profile=profile,
                           reduced_scopes=reduced or None,
                           ignore_blackout=ignore_blackout)
    sid = scan["id"]
    log(f"[snyk-aw] scan {sid} queued on target {tid} "
        f"(profile={profile or 'target-default'}"
        f"{', reduced scope' if reduced else ''}"
        f"{', ignore-blackout' if ignore_blackout else ''})")

    poll = max(5.0, float(getattr(cfg, "probely_poll_interval", 15.0) or 15.0))
    deadline = time.monotonic() + float(getattr(cfg, "probely_max_wait_minutes",
                                                180.0) or 180.0) * 60.0
    status = scan.get("status", "queued")
    cancelled = False

    def _emit_progress(sc: dict):
        if progress is None:
            return
        try:
            scanner = sc.get("scanner") or {}
            st = scanner.get("status") or []
            if isinstance(st, list) and len(st) >= 2 and st[1]:
                done, total = int(st[0]), int(st[1])
                progress(min(done, total), max(total, 1))
            else:
                phase = {"queued": 5, "started": 50, "finishing_up": 90,
                         "completed": 100, "completed_with_errors": 100,
                         "under_review": 100}.get(
                    sc.get("status", ""), 25)
                progress(phase, 100)
        except Exception:
            pass

    while True:
        if cancel.is_set() and not cancelled:
            log("[snyk-aw] cancel requested → cancelling cloud scan")
            try:
                client.cancel_scan(tid, sid)
            except ProbelyError as e:
                log(f"[snyk-aw] cancel call failed: {e}")
            cancelled = True
        if time.monotonic() > deadline:
            log("[snyk-aw] max wait exceeded → cancelling cloud scan")
            try:
                client.cancel_scan(tid, sid)
            except ProbelyError:
                pass
            cancelled = True
            break
        time.sleep(poll)
        try:
            sc = client.get_scan(tid, sid)
        except ProbelyError as e:
            log(f"[snyk-aw] poll error: {e}")
            continue
        status = sc.get("status", status)
        _emit_progress(sc)
        log(f"[snyk-aw] scan {sid} status={status} "
            f"(L{sc.get('lows', '?')}/M{sc.get('mediums', '?')}/H{sc.get('highs', '?')})")
        if status in _TERMINAL:
            break

    findings: list[dict] = []
    try:
        for f in client.iter_findings(tid, state="notfixed"):
            findings.append(_normalise_finding(f, default_category))
    except ProbelyError as e:
        log(f"[snyk-aw] could not list findings: {e}")

    _SVR = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    findings.sort(key=lambda x: -_SVR.get(x["severity"], 0))

    report_path = ""
    template = (getattr(cfg, "probely_compliance_report", "") or "").strip()
    if template and out_dir is not None:
        try:
            pdf = client.download_report(tid, sid, template)
            rp = out_dir / f"probely_report_{template}.pdf"
            rp.write_bytes(pdf)
            report_path = str(rp)
            log(f"[snyk-aw] compliance report ({template}) saved → {rp}")
        except ProbelyError as e:
            log(f"[snyk-aw] could not download {template} report: {e}")

    return {
        "status": status,
        "cancelled": cancelled or cancel.is_set(),
        "findings": findings,
        "target_id": tid,
        "scan_id": sid,
        "scan_url": f"{_app_base(cfg)}/targets/{tid}/scans/{sid}",
        "report_path": report_path,
    }


def run_api(cfg: ApiConfig, out_dir: Path,
            log: Callable[[str], None],
            cancel: Optional[threading.Event] = None,
            progress: Optional[Callable[[int, int], None]] = None) -> tuple[dict, Path]:
    cancel = cancel or threading.Event()
    out_path = out_dir / "api.json"

    def _write(s: dict) -> Path:
        out_path.write_text(json.dumps(s, indent=2), encoding="utf-8")
        return out_path

    spec_src = (getattr(cfg, "spec_source", "") or "").strip()
    base_url = (getattr(cfg, "base_url", "") or "").strip()
    api_url = base_url
    if not api_url and spec_src:
        try:
            opener, _, hdrs = _make_opener(cfg)
            spec = _api_load_spec(opener, hdrs, cfg, log)
            if isinstance(spec, dict):
                api_url = _api_base_url(spec, cfg, spec_src)
        except Exception as e:
            log(f"[snyk-aw] could not derive API base URL from spec: {e!r}")

    base_summary = {
        "target": api_url, "spec_source": spec_src, "profile": cfg.profile,
        "endpoints_total": 0, "endpoints_tested": 0,
        "cancelled": cancel.is_set(), "findings": [],
    }

    if not spec_src and not base_url:
        log("[snyk-aw] no API spec/URL configured — skipping API scan")
        return base_summary, _write(base_summary)
    if not api_url:
        base_summary["findings"] = [{
            "severity": "high", "title": "No API base URL",
            "url": spec_src, "evidence": "Could not determine the API server URL "
            "to register as a Probely target.", "cwe": "", "category": "spec"}]
        return base_summary, _write(base_summary)

    try:
        client = _Probely(cfg.probely_token, _resolve_api_base(cfg), log,
                          getattr(cfg, "probely_auth_scheme", "JWT"))
        who = client.whoami()
        log(f"[snyk-aw] authenticated as {who.get('name') or who.get('email') or '?'}")
        target = _ensure_target(client, cfg, url=api_url, is_api=True, log=log)
        result = _drive_scan(client, cfg, target, out_name="api.json",
                             default_category="api", log=log, cancel=cancel,
                             progress=progress, out_dir=out_dir)
    except ProbelyError as e:
        log(f"[snyk-aw] API scan failed: {e}")
        base_summary["findings"] = [{
            "severity": "high", "title": "Snyk API & Web scan failed",
            "url": api_url, "evidence": str(e), "cwe": "", "category": "spec"}]
        exc_summary = dict(base_summary)
        if getattr(e, "is_auth", False):
            exc_summary["auth_error"] = True
        return exc_summary, _write(exc_summary)

    summary = {
        "target": api_url, "spec_source": spec_src, "profile": cfg.profile,
        "endpoints_total": 0, "endpoints_tested": 0,
        "cancelled": result["cancelled"], "findings": result["findings"],
        "target_id": result["target_id"], "scan_id": result["scan_id"],
        "scan_url": result["scan_url"], "engine": "snyk-api-web",
        "report_path": result.get("report_path", ""),
    }
    log(f"[snyk-aw] API scan complete: {len(summary['findings'])} findings "
        f"({result['status']}) → {out_path}")
    return summary, _write(summary)


def run_dast(cfg: DastConfig, out_dir: Path,
             log: Callable[[str], None],
             cancel: Optional[threading.Event] = None,
             progress: Optional[Callable[[int, int], None]] = None) -> tuple[dict, Path]:
    cancel = cancel or threading.Event()
    out_path = out_dir / "dast.json"

    def _write(s: dict) -> Path:
        out_path.write_text(json.dumps(s, indent=2), encoding="utf-8")
        return out_path

    url = (getattr(cfg, "url", "") or "").strip()
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url

    base_summary = {
        "target": url, "final_url": url, "profile": cfg.profile,
        "auth_type": cfg.auth_type, "pages_visited": 0, "forms_discovered": 0,
        "relogins": 0, "cancelled": cancel.is_set(), "findings": [],
    }
    if not url or url == "https://":
        log("[snyk-aw] no DAST URL configured — skipping DAST scan")
        return base_summary, _write(base_summary)

    try:
        client = _Probely(cfg.probely_token, _resolve_api_base(cfg), log,
                          getattr(cfg, "probely_auth_scheme", "JWT"))
        who = client.whoami()
        log(f"[snyk-aw] authenticated as {who.get('name') or who.get('email') or '?'}")
        target = _ensure_target(client, cfg, url=url, is_api=False, log=log)
        result = _drive_scan(client, cfg, target, out_name="dast.json",
                             default_category="dast", log=log, cancel=cancel,
                             progress=progress, out_dir=out_dir)
    except ProbelyError as e:
        log(f"[snyk-aw] DAST scan failed: {e}")
        base_summary["findings"] = [{
            "severity": "high", "title": "Snyk API & Web scan failed",
            "url": url, "evidence": str(e), "cwe": "", "category": "dast"}]
        exc_summary = dict(base_summary)
        if getattr(e, "is_auth", False):
            exc_summary["auth_error"] = True
        return exc_summary, _write(exc_summary)

    summary = {
        "target": url, "final_url": url, "profile": cfg.profile,
        "auth_type": cfg.auth_type, "pages_visited": 0, "forms_discovered": 0,
        "relogins": 0, "cancelled": result["cancelled"],
        "findings": result["findings"],
        "target_id": result["target_id"], "scan_id": result["scan_id"],
        "scan_url": result["scan_url"], "engine": "snyk-api-web",
        "report_path": result.get("report_path", ""),
    }
    log(f"[snyk-aw] DAST scan complete: {len(summary['findings'])} findings "
        f"({result['status']}) → {out_path}")
    return summary, _write(summary)


def check_snyk_api_web(cfg, log: Callable[[str], None] = lambda *_: None) -> tuple[bool, str]:
    """Return (ok, message). Validates the token by calling /profile/.
    Wire this in Snyk_Scanner_GUI before launching the DAST/API stages, the same
    way ensure_snyk_ready() gates SCA/SAST."""
    token = getattr(cfg, "probely_token", "") or ""
    if not token:
        return False, "No Snyk session to reuse — sign in to Snyk (SSO) first."
    try:
        who = _Probely(token, _resolve_api_base(cfg), log,
                       getattr(cfg, "probely_auth_scheme", "JWT")).whoami()
        return True, f"Authenticated as {who.get('name') or who.get('email') or '?'}"
    except ProbelyError as e:
        return False, str(e)


def fetch_scan_profiles(cfg, target_type: str = "web",
                        log: Callable[[str], None] = lambda *_: None
                        ) -> list[tuple[str, str]]:
    """Return [(id, name), …] of the scan profiles available for ``target_type``
    ("web" or "api"). Built-in ids are plain (e.g. "normal", "full"); custom ones
    are prefixed "sp-". Returns [] on any error so callers can fall back to a
    static list without crashing."""
    token = getattr(cfg, "probely_token", "") or ""
    if not token:
        return []
    try:
        client = _Probely(token, _resolve_api_base(cfg), log,
                          getattr(cfg, "probely_auth_scheme", "JWT"))
        out: list[tuple[str, str]] = []
        for p in client.list_scan_profiles(target_type):
            pid = (p.get("id") or "").strip()
            name = (p.get("name") or pid).strip()
            if pid:
                out.append((pid, name))
        return out
    except ProbelyError as e:
        log(f"[snyk-aw] could not list scan profiles: {e}")
        return []
