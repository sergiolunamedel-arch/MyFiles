#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
import csv
import getpass
import json
import os
import sys
from datetime import datetime
from typing import Optional

import requests


BASE_URL = os.environ.get("SNOW_BASE_URL", "https://bancobasedev.service-now.com")
SYS_ID = os.environ.get("SNOW_CATALOG_SYS_ID", "799044769396c750af38b6ea6aba1080")
ORDER_URL = f"{BASE_URL}/api/sn_sc/servicecatalog/items/{SYS_ID}/order_now"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.environ.get("SNOW_TEST_LOG") or os.path.join(SCRIPT_DIR, "servicenow_test_log.csv")

APP_DATA_DIR = os.environ.get("SNOW_APP_DATA_DIR") or os.path.join(os.path.expanduser("~"), ".servicenow_ticket_tester")
try:
    os.makedirs(APP_DATA_DIR, exist_ok=True)
except OSError:
    pass

CANCEL_TABLE = os.environ.get("SNOW_CANCEL_TABLE", "sc_request")
CANCEL_STATE_FIELD = os.environ.get("SNOW_CANCEL_STATE_FIELD", "state")
CANCEL_STATE_VALUE = os.environ.get("SNOW_CANCEL_STATE", "Closed Cancelled")

CREDENTIALS_FILE = os.environ.get("SNOW_CREDENTIALS_FILE") or os.path.join(APP_DATA_DIR, "credentials.json")

DEFAULT_APP_NAME = os.environ.get("SNOW_APP_NAME", "Portal-Clientes")
DEFAULT_DESCRIPTION = os.environ.get(
    "SNOW_DESCRIPCION",
    "Solicitud de escaneo de seguridad conforme al calendario de revisiones periódicas.",
)


BASE_FIELDS = {
    "id_del_solicitante": "slunam",
    "nombre_del_solicitante": "Sergio Luna Medel",
    "correo_del_solicitante": "slunam@bancobase.com",
    "objetivo_de_la_solicitud": "Obtener solicitudes de escaneo y limpieza de falsos positivos",
    "nombre_de_la_aplicaci_n": DEFAULT_APP_NAME,
    "ambiente": "Desarrollo",
    "modo_ejecucion": "Baseline",
    "clasificaci_n_de_la_aplicaci_n": "MDP",
    "prioridad_": "Media",
    "owner_de_la_aplicaci_n2": "URL de la API",
    "descripci_n_de_la_solicitud_justificaci_n": DEFAULT_DESCRIPTION,
    "cuentas_con_url": "URL de la API",
}


SERVICES = {
    "sast_sca": {
        "field": "sast_sca",
        "extra": {
            "organizaci_n_en_snyk": "TEST-ORG",
        },
    },
    "dast": {
        "field": "dast",
        "extra": {
            "organizaci_n_en_snyk": "TEST-ORG",
            "requiere_triage": "No",
            "url_objetivo": "https://test.bancobase.com",
            "urls_a_excluir": "[]",
            "usar_cuenta_de_servicio_del_equipo": "Si",
        },
    },
    "api": {
        "field": "api",
        "extra": {
            "organizaci_n_en_snyk": "TEST-ORG",
            "tecnologia_api": "REST",
            "usar_cuenta_de_servicio_del_equipo": "Si",
            "url_de_la_api": "https://test.bancobase.com/api",
        },
    },
    "secretos": {
        "field": "escaneo_de_secretos",
        "extra": {
            "repositorio_s": "[{\"name\": \"test-repo\"}]",
            "ruta_monorepo": "/",
            "usar_cuenta_de_servicio_del_equipo": "Si",
        },
    },
    "triage": {
        "field": "triage",
        "extra": {},
    },
}


def build_payload(selected_services: list[str], ambiente: Optional[str] = None,
                   app_name: Optional[str] = None, descripcion: Optional[str] = None,
                   solicitante_id: Optional[str] = None, solicitante_nombre: Optional[str] = None,
                   solicitante_correo: Optional[str] = None,
                   overrides: Optional[dict] = None) -> dict:
    if not selected_services:
        raise ValueError("Debes seleccionar al menos un servicio")
    unknown = [s for s in selected_services if s not in SERVICES]
    if unknown:
        raise ValueError(f"Servicio(s) desconocido(s): {', '.join(unknown)}")

    fields = copy.deepcopy(BASE_FIELDS)
    if app_name:
        fields["nombre_de_la_aplicaci_n"] = app_name
    if descripcion:
        fields["descripci_n_de_la_solicitud_justificaci_n"] = descripcion
    if ambiente:
        fields["ambiente"] = ambiente
    if solicitante_id:
        fields["id_del_solicitante"] = solicitante_id
    if solicitante_nombre:
        fields["nombre_del_solicitante"] = solicitante_nombre
    if solicitante_correo:
        fields["correo_del_solicitante"] = solicitante_correo

    for name, spec in SERVICES.items():
        fields[spec["field"]] = "true" if name in selected_services else "false"

    for name in selected_services:
        fields.update(SERVICES[name]["extra"])

    if overrides:
        fields.update(overrides)

    return {"sysparm_quantity": "1", "variables": fields}


def load_saved_credentials() -> dict:
    if not os.path.isfile(CREDENTIALS_FILE):
        return {}
    try:
        with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_credentials(user: str = "", password: str = "", token: str = "") -> None:
    with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
        json.dump({"user": user, "password": password, "token": token}, f)
    try:
        os.chmod(CREDENTIALS_FILE, 0o600)
    except OSError:
        pass


def clear_saved_credentials() -> None:
    try:
        os.remove(CREDENTIALS_FILE)
    except FileNotFoundError:
        pass


def get_auth():
    token = os.environ.get("SNOW_TOKEN")
    if token:
        return None, {"Authorization": f"Bearer {token}"}

    saved = load_saved_credentials()
    if saved.get("token"):
        return None, {"Authorization": f"Bearer {saved['token']}"}

    user = os.environ.get("SNOW_USER") or saved.get("user") or input("Usuario ServiceNow: ")
    password = os.environ.get("SNOW_PASS") or saved.get("password") or getpass.getpass("Password ServiceNow: ")
    return (user, password), {}


def remember_auth(auth, extra_headers: dict) -> None:
    auth_header = extra_headers.get("Authorization", "")
    token = auth_header[len("Bearer "):] if auth_header.startswith("Bearer ") else ""
    user, password = auth if auth else ("", "")
    save_credentials(user=user or "", password=password or "", token=token)


def send_request(scenario_name: str, payload: dict, auth, extra_headers: dict, dry_run: bool,
                  log=print) -> dict:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    headers.update(extra_headers)

    if dry_run:
        log(f"--- [DRY RUN] {scenario_name} ---")
        log(json.dumps(payload, indent=2, ensure_ascii=False))
        return {"scenario": scenario_name, "status": "dry-run", "sys_id": "", "request_number": "", "error": ""}

    try:
        resp = requests.post(ORDER_URL, auth=auth, headers=headers, json=payload, timeout=30)
    except requests.RequestException as exc:
        log(f"[{scenario_name}] ERROR de red: {exc}")
        return {"scenario": scenario_name, "status": "network_error", "sys_id": "", "request_number": "", "error": str(exc)}

    result_row = {"scenario": scenario_name, "status": resp.status_code, "sys_id": "", "request_number": "", "error": ""}

    if resp.status_code in (200, 201):
        try:
            body = resp.json()
            result = body.get("result", {})
            result_row["request_number"] = result.get("request_number", "")
            result_row["sys_id"] = result.get("sys_id", "") or result.get("request_id", "")
            log(f"[{scenario_name}] OK ({resp.status_code}) -> request_number: {result_row['request_number']}")
        except (ValueError, KeyError) as exc:
            result_row["error"] = f"Respuesta OK pero no se pudo parsear: {exc}"
            log(f"[{scenario_name}] OK ({resp.status_code}) pero respuesta inesperada:\n{resp.text[:500]}")
    else:
        result_row["error"] = resp.text[:1000]
        log(f"[{scenario_name}] FALLÓ ({resp.status_code}):\n{resp.text[:1000]}")
        if "mandatory" in resp.text.lower():
            log(f"[{scenario_name}] Diagnosticando variables obligatorias faltantes...")
            missing = diagnose_missing_variables(payload, auth, extra_headers, log=log)
            if missing:
                result_row["error"] += f" | Variables obligatorias faltantes: {', '.join(missing)}"

    return result_row


def cancel_request(sys_id: str, auth, extra_headers: dict, log=print) -> dict:
    if not sys_id:
        return {"cancelled": False, "cleanup_error": "sin sys_id (no se puede cancelar)"}

    url = f"{BASE_URL}/api/now/table/{CANCEL_TABLE}/{sys_id}"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    headers.update(extra_headers)
    body = {
        CANCEL_STATE_FIELD: CANCEL_STATE_VALUE,
        "close_notes": "Cancelado automáticamente por test_servicenow_ticket.py (ticket de prueba)",
    }

    try:
        resp = requests.patch(url, auth=auth, headers=headers, json=body, timeout=30)
    except requests.RequestException as exc:
        log(f"  cleanup {sys_id}: ERROR de red: {exc}")
        return {"cancelled": False, "cleanup_error": str(exc)}

    if resp.status_code in (200, 201):
        log(f"  cleanup {sys_id}: cancelado OK")
        return {"cancelled": True, "cleanup_error": ""}

    log(f"  cleanup {sys_id}: FALLÓ ({resp.status_code}): {resp.text[:300]}")
    return {"cancelled": False, "cleanup_error": f"{resp.status_code}: {resp.text[:300]}"}


def get_audit_history(table: str, sys_id: str, auth, extra_headers: dict, log=print) -> list[dict]:
    url = (f"{BASE_URL}/api/now/table/sys_audit"
           f"?sysparm_query=tablename={table}^documentkey={sys_id}^ORDERBYsys_created_on"
           f"&sysparm_fields=fieldname,oldvalue,newvalue,user,sys_created_on,reason"
           f"&sysparm_display_value=true"
           f"&sysparm_limit=200")
    headers = {"Accept": "application/json"}
    headers.update(extra_headers)

    try:
        resp = requests.get(url, auth=auth, headers=headers, timeout=30)
    except requests.RequestException as exc:
        log(f"ERROR de red al consultar auditoría: {exc}")
        return []

    if resp.status_code != 200:
        log(f"No se pudo consultar auditoría ({resp.status_code}): {resp.text[:1000]}")
        return []

    try:
        rows = resp.json().get("result", [])
    except ValueError:
        log("Respuesta no es JSON válido al consultar auditoría.")
        return []

    if not rows:
        log(f"(sin registros de auditoría para {table}/{sys_id} — revisa que el sys_id/tabla sean "
            f"correctos, o que tu usuario tenga permiso de lectura sobre sys_audit)")
        return rows

    log(f"--- Historial de cambios de {table}/{sys_id} (quién cambió qué, y cuándo) ---")
    for row in rows:
        who = row.get("user", "") or "(sistema/desconocido)"
        log(f"  {row.get('sys_created_on', '')}  [{who}]  {row.get('fieldname', '')}: "
            f"'{row.get('oldvalue', '')}' -> '{row.get('newvalue', '')}'"
            + (f"   motivo: {row.get('reason')}" if row.get("reason") else ""))
    log("  >>> Si el cambio de 'state' a Closed/Cancelled aparece con un usuario del sistema, "
        "una cuenta de servicio, o un Flow/Workflow (no tu usuario real y no justo después del "
        "mensaje 'Limpiando tickets de prueba...' en el log de este script), el cierre lo está "
        "haciendo ServiceNow del lado del servidor, no este script.")
    return rows


def list_variables(auth, extra_headers: dict, mandatory_only: bool = True, log=print) -> list[dict]:
    query = f"cat_item={SYS_ID}"
    if mandatory_only:
        query += "^mandatory=true"
    url = (f"{BASE_URL}/api/now/table/item_option_new"
           f"?sysparm_query={query}^ORDERBYorder"
           f"&sysparm_fields=name,question_text,mandatory,active,order,type"
           f"&sysparm_display_value=true"
           f"&sysparm_limit=200")
    headers = {"Accept": "application/json"}
    headers.update(extra_headers)

    try:
        resp = requests.get(url, auth=auth, headers=headers, timeout=30)
    except requests.RequestException as exc:
        log(f"ERROR de red al listar variables: {exc}")
        return []

    if resp.status_code != 200:
        log(f"No se pudieron listar variables ({resp.status_code}): {resp.text[:1000]}")
        return []

    try:
        rows = resp.json().get("result", [])
    except ValueError:
        log("Respuesta no es JSON válido al listar variables.")
        return []

    if not rows:
        log("(sin resultados — revisa que SNOW_CATALOG_SYS_ID sea correcto, "
            "o que tu usuario tenga permiso de lectura sobre item_option_new)")
        return rows

    label = "obligatorias" if mandatory_only else "todas las"
    log(f"Variables {label} del catalog item ({len(rows)}):")
    for row in rows:
        flag = "OBLIGATORIA" if str(row.get("mandatory")).lower() == "true" else "opcional"
        active = "" if str(row.get("active", "true")).lower() == "true" else " [INACTIVA]"
        tipo = row.get("type", "")
        log(f"  [{flag}]{active} {row.get('name')}  (tipo: {tipo})  —  {row.get('question_text')}")
    return rows


def diagnose_missing_variables(payload: dict, auth, extra_headers: dict, log=print) -> list[str]:
    mandatory_vars = list_variables(auth, extra_headers, mandatory_only=True, log=lambda *_: None)
    sent_names = set(payload.get("variables", {}).keys())
    missing = [v.get("name") for v in mandatory_vars if v.get("name") not in sent_names]

    if missing:
        log("  >>> Variables obligatorias que FALTAN en el payload enviado:")
        for name in missing:
            v = next((v for v in mandatory_vars if v.get("name") == name), {})
            log(f"       - {name}  (tipo: {v.get('type', '')})  —  {v.get('question_text', '')}")
    elif mandatory_vars:
        reference_like = [v for v in mandatory_vars
                           if v.get("name") in sent_names
                           and any(kw in str(v.get("type", "")).lower() for kw in ("reference", "lookup", "list collector"))]
        if reference_like:
            log("  >>> Todas las variables obligatorias se enviaron, pero estas son de tipo "
                "referencia/lookup: si el valor no existe como registro real en tu instancia, "
                "ServiceNow lo trata como vacío y por eso sigue marcando 'mandatory':")
            for v in reference_like:
                name = v.get("name")
                log(f"       - {name} = '{payload['variables'].get(name)}'  (tipo: {v.get('type')})")
        else:
            log("  >>> Todas las variables marcadas 'obligatorias' sí se enviaron; el "
                "rechazo probablemente es por un VALOR inválido (ej. una opción de choice "
                "que no existe en tu instancia), no por un campo faltante.")
    else:
        log("  >>> No se pudo obtener la lista de variables obligatorias para comparar "
            "(revisa el mensaje anterior).")

    return missing


def get_variable_detail(auth, extra_headers: dict, name: str, log=print) -> dict:
    url = (f"{BASE_URL}/api/now/table/item_option_new"
           f"?sysparm_query=cat_item={SYS_ID}^name={name}"
           f"&sysparm_fields=name,question_text,type,mandatory,active,order,help_text,default_value,tooltip"
           f"&sysparm_display_value=true"
           f"&sysparm_limit=5")
    headers = {"Accept": "application/json"}
    headers.update(extra_headers)

    try:
        resp = requests.get(url, auth=auth, headers=headers, timeout=30)
    except requests.RequestException as exc:
        log(f"ERROR de red al consultar '{name}': {exc}")
        return {}

    if resp.status_code != 200:
        log(f"No se pudo consultar '{name}' ({resp.status_code}): {resp.text[:1000]}")
        return {}

    try:
        rows = resp.json().get("result", [])
    except ValueError:
        log("Respuesta no es JSON válido.")
        return {}

    if not rows:
        log(f"(no se encontró la variable '{name}' en este catalog item)")
        return {}

    row = rows[0]
    log(f"--- Detalle de '{name}' ---")
    for key in ("name", "question_text", "type", "mandatory", "active", "order",
                "help_text", "tooltip", "default_value"):
        val = row.get(key, "")
        if val:
            log(f"  {key}: {val}")
    return row


def list_recent_tickets(auth, extra_headers: dict, limit: int = 25, log=print) -> list[dict]:
    url = (f"{BASE_URL}/api/now/table/sc_req_item"
           f"?sysparm_query=cat_item={SYS_ID}^ORDERBYDESCsys_created_on"
           f"&sysparm_fields=sys_id,number,state,short_description,sys_created_on,request"
           f"&sysparm_display_value=all"
           f"&sysparm_limit={limit}")
    headers = {"Accept": "application/json"}
    headers.update(extra_headers)

    try:
        resp = requests.get(url, auth=auth, headers=headers, timeout=30)
    except requests.RequestException as exc:
        log(f"ERROR de red al listar tickets: {exc}")
        return []

    if resp.status_code != 200:
        log(f"No se pudieron listar tickets ({resp.status_code}): {resp.text[:1000]}")
        return []

    try:
        rows = resp.json().get("result", [])
    except ValueError:
        log("Respuesta no es JSON válido al listar tickets.")
        return []

    def _raw(field):
        return field.get("value", "") if isinstance(field, dict) else (field or "")

    def _readable(field):
        return field.get("display_value", "") if isinstance(field, dict) else (field or "")

    tickets = []
    for row in rows:
        tickets.append({
            "ritm_sys_id": _raw(row.get("sys_id")),
            "ritm_number": _raw(row.get("number")),
            "request_sys_id": _raw(row.get("request")),
            "state": _readable(row.get("state")),
            "short_description": _readable(row.get("short_description"))[:80],
            "created": _raw(row.get("sys_created_on")),
        })

    if not tickets:
        log("(sin tickets encontrados para este catalog item)")
    return tickets


def cleanup_results(results: list[dict], auth, extra_headers: dict, log=print) -> None:
    for row in results:
        if row.get("status") in (200, 201) and row.get("sys_id"):
            cleanup = cancel_request(row["sys_id"], auth, extra_headers, log=log)
            row["cleanup_status"] = "cancelado" if cleanup["cancelled"] else "error"
            row["cleanup_error"] = cleanup["cleanup_error"]
        else:
            row["cleanup_status"] = "n/a"
            row["cleanup_error"] = ""


def log_results(rows: list[dict], log_file: str = LOG_FILE) -> None:
    file_exists = os.path.isfile(log_file)
    fieldnames = ["timestamp", "scenario", "status", "sys_id", "request_number",
                  "error", "cleanup_status", "cleanup_error"]
    with open(log_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        for row in rows:
            row_out = {"timestamp": datetime.now().isoformat(timespec="seconds")}
            row_out.update({k: row.get(k, "") for k in fieldnames if k != "timestamp"})
            writer.writerow(row_out)
    print(f"\nResultados agregados a {log_file}")


def main():
    parser = argparse.ArgumentParser(description="Prueba el template de ticket de ServiceNow.")
    parser.add_argument("--service", action="append", metavar="NAME", choices=list(SERVICES.keys()),
                         help="Servicio a incluir en el ticket (repetible: --service dast --service api). Si no se especifica, se incluyen todos en un solo ticket.")
    parser.add_argument("--ambiente", help="Sobrescribe el ambiente (ej. 'Producción' para probar la nota de validación).")
    parser.add_argument("--app-name", help=f"Nombre de la aplicación a usar en el ticket (default: '{DEFAULT_APP_NAME}').")
    parser.add_argument("--descripcion", help="Descripción/justificación de la solicitud (default: texto genérico de revisión periódica).")
    parser.add_argument("--solicitante-nombre", metavar="NOMBRE",
                         help="Nombre de la persona a cuyo nombre quedará el ticket (para probar con distintas personas).")
    parser.add_argument("--solicitante-correo", metavar="CORREO",
                         help="Correo de la persona a cuyo nombre quedará el ticket.")
    parser.add_argument("--solicitante-id", metavar="USUARIO",
                         help="ID/usuario ServiceNow de la persona a cuyo nombre quedará el ticket (opcional; por default se usa el mismo de siempre).")
    parser.add_argument("--var", action="append", metavar="NAME=VALUE",
                         help="Sobrescribe o agrega una variable del payload (repetible). Úsalo para dar valores REALES de organización/repositorio, ej: --var organizaci_n_en_snyk=MiOrgReal")
    parser.add_argument("--dry-run", action="store_true", help="Solo imprime el payload, no llama a la API.")
    parser.add_argument("--no-cleanup", action="store_true", help="No cancela los tickets de prueba al terminar.")
    parser.add_argument("--list", action="store_true", help="Lista las ramas disponibles y sale.")
    parser.add_argument("--inspect", action="store_true",
                         help="Consulta a ServiceNow cuáles variables son realmente obligatorias en el catalog item y sale (no crea tickets).")
    parser.add_argument("--inspect-all", action="store_true",
                         help="Como --inspect pero muestra todas las variables, no sólo las obligatorias.")
    parser.add_argument("--inspect-field", metavar="NAME",
                         help="Consulta el detalle completo (tipo, texto de ayuda, valor por defecto) de una variable específica y sale.")
    parser.add_argument("--list-tickets", nargs="?", const=25, type=int, metavar="N",
                         help="Lista los últimos N tickets (RITM) de este catalog item y sale (default 25).")
    parser.add_argument("--audit", metavar="SYS_ID",
                         help="Muestra el historial de cambios (sys_audit) de un registro por su sys_id, "
                              "para diagnosticar QUIÉN o QUÉ lo cerró/canceló (¿tu script, un usuario, o un Flow de ServiceNow?).")
    parser.add_argument("--audit-table", default="sc_req_item", metavar="TABLE",
                         help="Tabla del registro para --audit (default: sc_req_item, el RITM). "
                              "Usa 'sc_request' para auditar el REQ en vez del RITM.")
    parser.add_argument("--cancel", nargs="+", metavar="REQ_SYS_ID",
                         help="Cancela el/los REQ indicados por su sys_id (ver --list-tickets) y sale.")
    parser.add_argument("--remember", action="store_true",
                         help="Guarda las credenciales usadas en este comando (texto plano, junto al script).")
    parser.add_argument("--forget-credentials", action="store_true",
                         help="Borra las credenciales guardadas y sale.")
    parser.add_argument("--gui", action="store_true", help="Lanza la interfaz gráfica en vez del CLI.")
    args = parser.parse_args()

    if args.forget_credentials:
        clear_saved_credentials()
        print("Credenciales guardadas eliminadas.")
        return

    if args.gui:
        import gui_servicenow_tester
        gui_servicenow_tester.launch()
        return

    if args.list:
        print("Servicios disponibles:", ", ".join(SERVICES.keys()))
        return

    if args.inspect or args.inspect_all:
        auth, extra_headers = get_auth()
        if args.remember:
            remember_auth(auth, extra_headers)
        list_variables(auth, extra_headers, mandatory_only=not args.inspect_all)
        return

    if args.inspect_field:
        auth, extra_headers = get_auth()
        if args.remember:
            remember_auth(auth, extra_headers)
        get_variable_detail(auth, extra_headers, args.inspect_field)
        return

    if args.list_tickets is not None:
        auth, extra_headers = get_auth()
        if args.remember:
            remember_auth(auth, extra_headers)
        tickets = list_recent_tickets(auth, extra_headers, limit=args.list_tickets)
        for t in tickets:
            print(f"{t['ritm_number']:<14} {t['state']:<22} {t['created']:<20} "
                  f"{t['short_description']:<40} REQ sys_id: {t['request_sys_id']}")
        return

    if args.audit:
        auth, extra_headers = get_auth()
        if args.remember:
            remember_auth(auth, extra_headers)
        get_audit_history(args.audit_table, args.audit, auth, extra_headers)
        return

    if args.cancel:
        auth, extra_headers = get_auth()
        if args.remember:
            remember_auth(auth, extra_headers)
        for sys_id in args.cancel:
            cancel_request(sys_id, auth, extra_headers)
        return

    selected_services = args.service if args.service else list(SERVICES.keys())

    overrides = {}
    if args.var:
        for kv in args.var:
            if "=" not in kv:
                print(f"Ignorando --var mal formado (usa NAME=VALUE): {kv}")
                continue
            k, v = kv.split("=", 1)
            overrides[k] = v

    auth, extra_headers = (None, {}) if args.dry_run else get_auth()
    if args.remember and not args.dry_run:
        remember_auth(auth, extra_headers)

    label = "+".join(selected_services)
    payload = build_payload(selected_services, ambiente=args.ambiente, app_name=args.app_name,
                             descripcion=args.descripcion, solicitante_id=args.solicitante_id,
                             solicitante_nombre=args.solicitante_nombre,
                             solicitante_correo=args.solicitante_correo, overrides=overrides)
    results = [send_request(label, payload, auth, extra_headers, args.dry_run)]

    if args.dry_run:
        print("\n(dry-run: nada se envió ni se guardó en el log)")
        return

    print(f"[config] Limpieza automática (cancelar al terminar): "
          f"{'DESACTIVADA (--no-cleanup)' if args.no_cleanup else 'ACTIVADA'}")
    if not args.no_cleanup:
        print("\nLimpiando tickets de prueba...")
        cleanup_results(results, auth, extra_headers)
    else:
        for row in results:
            row["cleanup_status"] = "omitido"
            row["cleanup_error"] = ""

    log_results(results)


if __name__ == "__main__":
    sys.exit(main())
