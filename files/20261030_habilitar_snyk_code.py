"""Activa Snyk Code (SAST) en todas las organizaciones del grupo de Snyk de la empresa.

Equivale a ir a cada organización → Settings → Snyk Code → «Enabled» → Save changes, vía la API REST oficial:
    GET   /rest/orgs/{org_id}/settings/sast      (ver estado)
    PATCH /rest/orgs/{org_id}/settings/sast      (sast_enabled = true; requiere permiso «Edit Organization»)

Credencial (la primera que exista):
    1. Variable de entorno SNYK_TOKEN (token de API personal o de una cuenta de servicio con rol de admin).
    2. La sesión de la CLI de Snyk de esta PC (la misma con la que se usa ScannerBase: `snyk auth`).

Uso (desde una terminal en la PC del admin):
    python habilitar_snyk_code.py                 → SOLO MUESTRA qué organizaciones tienen Snyk Code apagado
    python habilitar_snyk_code.py --apply         → lo activa en todas las que lo tengan apagado
    python habilitar_snyk_code.py --group <ID>    → limita a ese grupo (por defecto, el de banco-base-default)
    python habilitar_snyk_code.py --only "Core FX" --apply   → solo las orgs cuyo nombre contenga ese texto

No reimporta proyectos ni cambia nada más: los escaneos desde la CLI (ScannerBase) funcionan en cuanto se activa.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

VERSION = "2024-10-15"
DEFAULT_ORG = "7c545e26-1865-4ce9-a2e5-2b8c1c215e62"  # banco-base-default (para deducir el grupo)
NOWIN = {"creationflags": 0x08000000} if os.name == "nt" else {}


# ── Credencial ──────────────────────────────────────────────────────────────────────────────────────────────────────
def _snyk_exe() -> str:
    """La misma búsqueda que ScannerBase: PATH y, si no está ahí, las carpetas donde se instala la CLI."""
    if exe := shutil.which("snyk"):
        return exe
    for var, sub in (("LOCALAPPDATA", r"snyk\bin"), ("LOCALAPPDATA", "snyk"), ("APPDATA", "npm")):
        if os.environ.get(var):
            for name in ("snyk.exe", "snyk.cmd", "snyk"):
                p = os.path.join(os.environ[var], sub, name)
                if os.path.isfile(p):
                    return p
    return ""


def _config_files() -> list[str]:
    c = [os.path.join(os.environ[k], "configstore", "snyk.json") for k in ("APPDATA", "LOCALAPPDATA")
         if os.environ.get(k)]
    c += [os.path.join(os.path.expanduser("~"), ".config", "configstore", "snyk.json")]
    return [p for p in c if os.path.isfile(p)]


def _cfg(key: str) -> str:
    """Lee la sesión directo del archivo de configuración de la CLI (como ScannerBase); si no, vía `snyk config get`."""
    for p in _config_files():
        try:
            with open(p, encoding="utf-8") as f:
                v = json.load(f).get(key)
            if v not in (None, "", "undefined", "null"):
                return v if isinstance(v, str) else json.dumps(v)
        except Exception:
            pass
    return _snyk("config", "get", key)


def _snyk(*args, timeout=60) -> str:
    exe = _snyk_exe()
    if not exe:
        return ""
    try:
        r = subprocess.run([exe, *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, **NOWIN)
        v = (r.stdout or "").strip()
        return "" if v.lower() in ("", "undefined", "null", "not set") else v
    except Exception:
        return ""


def _jwt_api(token: str) -> str:
    try:
        part = token.split(".")[1]
        cl = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        for v in [*(cl.get("aud") if isinstance(cl.get("aud"), list) else [cl.get("aud")]), cl.get("iss")]:
            if isinstance(v, str) and v.startswith("https://api.") and "snyk.io" in v:
                return v.split("/", 3)[0] + "//" + v.split("/", 3)[2]
    except Exception:
        pass
    return ""


def credential() -> tuple[str, str]:
    """(encabezado Authorization, URL base de la API)."""
    base = os.environ.get("SNYK_API", "").rstrip("/").removesuffix("/v1").removesuffix("/api") or ""
    if tok := os.environ.get("SNYK_TOKEN", "").strip():
        return f"token {tok}", base or "https://api.snyk.io"
    if api := _cfg("api"):
        return f"token {api}", base or "https://api.snyk.io"
    raw = _cfg("INTERNAL_OAUTH_TOKEN_STORAGE")
    if raw:
        _snyk("whoami", "--experimental")  # obliga a la CLI a renovar el token OAuth si expiró
        raw = _cfg("INTERNAL_OAUTH_TOKEN_STORAGE") or raw
        try:
            at = json.loads(raw).get("access_token", "")
        except Exception:
            at = raw
        if at:
            return f"Bearer {at}", base or _jwt_api(at) or "https://api.snyk.io"
    keys = []
    for p in _config_files():
        try:
            with open(p, encoding="utf-8") as f:
                keys += [f"{p}: {sorted(json.load(f))}"]
        except Exception as e:
            keys += [f"{p}: ilegible ({e!r})"]
    sys.exit("No se encontró una sesión de Snyk.\n"
             f"  CLI de Snyk: {_snyk_exe() or 'NO encontrada'}\n"
             f"  Archivos de configuración: {'; '.join(keys) or 'ninguno'}\n"
             "Inicie sesión en ScannerBase (o con `snyk auth`) o defina SNYK_TOKEN, y vuelva a intentar.")


# ── HTTP ────────────────────────────────────────────────────────────────────────────────────────────────────────────
_CTX = [ssl.create_default_context()]
for _ca in (os.environ.get("NODE_EXTRA_CA_CERTS"), os.environ.get("REQUESTS_CA_BUNDLE"), os.environ.get("SSL_CERT_FILE")):
    if _ca and os.path.isfile(_ca):
        try:
            _CTX[0].load_verify_locations(_ca)
        except Exception:
            pass


def api(method: str, url: str, auth: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": auth, "Accept": "application/vnd.api+json", "Content-Type": "application/vnd.api+json",
        "User-Agent": "ScannerBase-admin"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30, context=_CTX[0]) as r:
                txt = r.read().decode("utf-8", "replace")
                return json.loads(txt) if txt.strip() else {}
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 3:  # límite de peticiones: espera y reintenta
                time.sleep(int(e.headers.get("Retry-After") or 5))
                continue
            detail = e.read().decode("utf-8", "replace")[:300]
            raise RuntimeError(f"HTTP {e.code}: {detail}") from None
        except (ssl.SSLError, urllib.error.URLError) as e:
            if "CERTIFICATE" in repr(e).upper() and _CTX[0].verify_mode != ssl.CERT_NONE:
                print("  [tls] el proxy corporativo rompe la verificación TLS — se reintenta sin verificar "
                      "(defina NODE_EXTRA_CA_CERTS con la CA de la empresa para evitarlo).")
                ctx = ssl.create_default_context()
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                _CTX[0] = ctx
                continue
            raise
    raise RuntimeError("demasiados reintentos")


def paged(url: str, auth: str, base: str) -> list:
    out = []
    for _ in range(50):
        d = api("GET", url, auth)
        out += d.get("data") or []
        nxt = (d.get("links") or {}).get("next")
        if not nxt:
            break
        url = nxt if nxt.startswith("http") else base + (nxt if nxt.startswith("/rest") else "/rest" + nxt)
    return out


# ── Lógica ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def list_orgs(auth: str, base: str, group: str) -> list[dict]:
    mine = paged(f"{base}/rest/orgs?version={VERSION}&limit=100", auth, base)
    if not group:
        groups = [o["attributes"].get("group_id") for o in mine if o.get("id") == DEFAULT_ORG]
        groups = groups or [o["attributes"].get("group_id") for o in mine
                            if not o["attributes"].get("is_personal") and o["attributes"].get("group_id")]
        group = groups[0] if groups else ""
    orgs = mine
    if group:
        try:  # un admin de grupo ve TODAS las orgs del grupo, no solo en las que es miembro
            orgs = paged(f"{base}/rest/groups/{group}/orgs?version={VERSION}&limit=100", auth, base)
        except Exception as e:
            print(f"  (no se pudo listar el grupo completo [{e}] — se usan solo las orgs de las que es miembro)")
            orgs = [o for o in mine if o["attributes"].get("group_id") == group]
    res = [{"id": o["id"], "name": (o.get("attributes") or {}).get("name") or o["id"]}
           for o in orgs if not (o.get("attributes") or {}).get("is_personal")]
    print(f"Grupo: {group or '(desconocido)'} · {len(res)} organización(es)")
    return sorted(res, key=lambda o: o["name"].lower())


def main() -> int:
    ap = argparse.ArgumentParser(description="Activa Snyk Code en las organizaciones de Snyk de la empresa.")
    ap.add_argument("--apply", action="store_true", help="aplica los cambios (sin esto solo muestra el estado)")
    ap.add_argument("--group", default="", help="ID del grupo de Snyk (por defecto, el de banco-base-default)")
    ap.add_argument("--only", default="", help="solo orgs cuyo nombre contenga este texto")
    a = ap.parse_args()
    auth, base = credential()
    print(f"API: {base}  ·  modo: {'APLICAR' if a.apply else 'solo lectura (use --apply para activar)'}\n")
    orgs = [o for o in list_orgs(auth, base, a.group) if a.only.lower() in o["name"].lower()]
    off, done, errors = [], [], []
    for o in orgs:
        url = f"{base}/rest/orgs/{o['id']}/settings/sast?version={VERSION}"
        try:
            cur = (api("GET", url, auth).get("data") or {})
            on = bool((cur.get("attributes") or {}).get("sast_enabled"))
        except Exception as e:
            errors.append((o, f"no se pudo leer: {e}"))
            print(f"  ?  {o['name']}  — no se pudo leer ({e})")
            continue
        if on:
            print(f"  ✓  {o['name']}  — ya activado")
            continue
        off.append(o)
        if not a.apply:
            print(f"  ✕  {o['name']}  — APAGADO")
            continue
        body = {"data": {"id": o["id"], "type": cur.get("type") or "sast_settings",
                         "attributes": {"sast_enabled": True}}}
        try:
            api("PATCH", url, auth, body)
            done.append(o)
            print(f"  →  {o['name']}  — ACTIVADO")
        except Exception as e:
            errors.append((o, str(e)))
            print(f"  !  {o['name']}  — error al activar: {e}")
    print(f"\nResumen: {len(orgs)} org(s) · {len(off)} con Snyk Code apagado"
          + (f" · {len(done)} activada(s)" if a.apply else "") + (f" · {len(errors)} error(es)" if errors else ""))
    if errors and any("403" in m for _, m in errors):
        print("Los errores 403 significan que esta cuenta no tiene permiso «Edit Organization» en esas orgs "
              "(se necesita Group Admin u Org Admin).")
    if off and not a.apply:
        print("Para activarlo en todas las anteriores, vuelva a correr con --apply.")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
