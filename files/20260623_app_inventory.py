
from __future__ import annotations

import json
import re
import threading
import tkinter as tk
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

# Risk-tier mapping used in the inventory dashboard
_RISK_COLORS_LIGHT = {
    "Crítico": "#c8102e",
    "Alto":     "#e26020",
    "Medio":   "#d4a017",
    "Bajo":      "#1a7a4a",
    "Ninguno":     "#5a6475",
}
_RISK_COLORS_DARK = {
    "Crítico": "#f08090",
    "Alto":     "#f4a460",
    "Medio":   "#f0d060",
    "Bajo":      "#5fe0a0",
    "Ninguno":     "#8892a4",
}

# Standard technology stack choices (inspired by OWASP SAMM)
_TECH_STACKS = [
    "Python", "Node.js / JavaScript", "Java / Spring", "C# / .NET",
    "Go", "Ruby on Rails", "PHP", "Rust", "C / C++", "Kotlin / Android",
    "Swift / iOS", "React / Vue / Angular (SPA)", "Mobile (React Native)",
    "Microservicios", "Serverless / Lambda", "Otro",
]

# Deployment environment options
_ENVIRONMENTS = [
    "Producción", "Preproducción / Staging", "QA / Pruebas",
    "Desarrollo", "Interno / Intranet", "Nube (AWS)", "Nube (Azure)",
    "Nube (GCP)", "En sitio (On-Premise)", "Híbrido",
]

# Application type (affects which scan stages make sense)
_APP_TYPES = [
    "Aplicación Web", "API REST", "API GraphQL", "App Móvil (iOS)",
    "App Móvil (Android)", "Aplicación de Escritorio", "Herramienta CLI / Script",
    "Microservicio", "Pipeline de Datos", "Proceso por Lotes / Trabajo en Segundo Plano",
    "IoT / Embebido", "Librería / SDK", "Otro",
]

# Business criticality aligned with ISO 27001 asset classification
_CRITICALITY_LEVELS = [
    "Crítico para la Misión",   # Inactividad = pérdida de ingresos / incumplimiento regulatorio
    "Crítico para el Negocio",  # Operaciones clave afectadas
    "Importante",               # Impacto significativo pero tolerable
    "Estándar",                 # Función normal del negocio
    "Bajo",                     # Impacto mínimo si no está disponible
]

# Compliance frameworks that may apply
_COMPLIANCE_TAGS = [
    "PCI-DSS", "PCI-DSS v4", "ISO 27001", "ISO 27001:2022",
    "SOC 2 Type II", "NIST CSF", "NIST SP 800-53",
    "OWASP Top-10", "OWASP ASVS", "CIS Benchmarks",
    "GDPR", "LFPDPPP (Mexico)", "CNBV Circular", "DORA (EU)",
    "HIPAA", "FedRAMP", "NOM-151", "Ninguno",
]

# Data classification aligned with banking sector standards
_DATA_CLASSIFICATION = [
    "Confidencial — Financiero",  # Números de cuenta, saldos, transacciones
    "Confidencial — Personal",    # PII / SPEI / CLABE
    "Restringido",                # Datos internos de negocio
    "Interno",                    # Datos internos no sensibles
    "Público",                    # Marketing / datos de cara al público
]

_EMPTY_APP: dict = {
    # ── Identity ──────────────────────────────────────────────────────────────
    "id":            "",          # slug derived from name
    "name":          "",
    "description":   "",
    "owner":         "",          # responsible team or person
    "owner_email":   "",
    "created_at":    "",
    "updated_at":    "",
    # ── Classification ────────────────────────────────────────────────────────
    "app_type":      _APP_TYPES[0],
    "tech_stack":    _TECH_STACKS[0],
    "environment":   _ENVIRONMENTS[0],
    "criticality":   _CRITICALITY_LEVELS[1],
    "data_class":    _DATA_CLASSIFICATION[0],
    "compliance":    [],           # list of tags
    "repo_url":      "",
    "ci_pipeline":   "",
    # ── Scan configuration (mirrors ScannerApp fields) ────────────────────────
    "target_path":   "",
    "dast_url":      "",
    "api_spec":      "",
    "scan_stages":   ["sca", "code"],
    # ── Cumulative vulnerability counts (updated after each scan) ─────────────
    "last_scan":     None,         # ISO datetime string
    "last_mode":     "",
    "vuln_critical": 0,
    "vuln_high":     0,
    "vuln_medium":   0,
    "vuln_low":      0,
    "vuln_total":    0,
    "secrets_total": 0,
    "risk_tier":     "Ninguno",       # derived: Critical/High/Medium/Low/None
    # ── History: list of {"ts","mode","critical","high","medium","low","total"} ─
    "scan_history":  [],
    # ── Notes ─────────────────────────────────────────────────────────────────
    "notes":         "",
}


def _slugify(name: str) -> str:
    """Convert a human name to a safe filename slug."""
    s = name.strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[\s_-]+", "_", s)
    return s[:48] or "app"


def _risk_tier(critical: int, high: int, medium: int, low: int) -> str:
    if critical:  return "Crítico"
    if high:      return "Alto"
    if medium:    return "Medio"
    if low:       return "Bajo"
    return "Ninguno"


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


# ─────────────────────────────────────────────────────────────────────────────
# Persistence helpers
# ─────────────────────────────────────────────────────────────────────────────

class AppInventoryStore:
    """Thread-safe JSON store for application profiles."""

    def __init__(self, reports_root: Path):
        self._lock   = threading.Lock()
        self.inv_dir = reports_root / "inventory"
        self.inv_dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self.inv_dir / "_index.json"

    # ── internal ──────────────────────────────────────────────────────────────

    def _read_index(self) -> list[str]:
        """Return ordered list of app IDs."""
        try:
            if self._index_path.exists():
                return json.loads(self._index_path.read_text("utf-8"))
        except Exception:
            pass
        # Recover from disk: any .json that isn't the index
        ids = sorted(
            p.stem for p in self.inv_dir.glob("*.json")
            if p.name != "_index.json"
        )
        self._write_index(ids)
        return ids

    def _write_index(self, ids: list[str]) -> None:
        self._index_path.write_text(json.dumps(ids, indent=2), "utf-8")

    def _app_path(self, app_id: str) -> Path:
        return self.inv_dir / f"{app_id}.json"

    # ── public API ────────────────────────────────────────────────────────────

    def list_apps(self) -> list[dict]:
        """Return all app dicts in index order."""
        with self._lock:
            ids = self._read_index()
            apps = []
            for aid in ids:
                p = self._app_path(aid)
                if p.exists():
                    try:
                        apps.append(json.loads(p.read_text("utf-8")))
                    except Exception:
                        pass
            return apps

    def get_app(self, app_id: str) -> Optional[dict]:
        with self._lock:
            p = self._app_path(app_id)
            if p.exists():
                try:
                    return json.loads(p.read_text("utf-8"))
                except Exception:
                    pass
        return None

    def save_app(self, app: dict) -> None:
        """Create or update an app profile. Generates id if missing."""
        with self._lock:
            if not app.get("id"):
                app["id"] = _slugify(app.get("name", "app"))
            # Deduplicate slug
            existing = self._read_index()
            if app["id"] not in existing:
                # ensure uniqueness
                base = app["id"]; n = 1
                while (self.inv_dir / f"{app['id']}.json").exists():
                    app["id"] = f"{base}_{n}"; n += 1
                existing.append(app["id"])
                self._write_index(existing)
            app["updated_at"] = _now()
            if not app.get("created_at"):
                app["created_at"] = app["updated_at"]
            self._app_path(app["id"]).write_text(
                json.dumps(app, indent=2, ensure_ascii=False), "utf-8")

    def delete_app(self, app_id: str) -> None:
        with self._lock:
            ids = self._read_index()
            if app_id in ids:
                ids.remove(app_id)
                self._write_index(ids)
            p = self._app_path(app_id)
            if p.exists():
                p.unlink()

    def record_scan(self, app_id: str, meta: dict) -> None:
        """Update vuln counts from a completed scan meta dict."""
        app = self.get_app(app_id)
        if app is None:
            return
        counts = meta.get("counts", {})
        c = int(counts.get("critical", 0) or 0)
        h = int(counts.get("high", 0) or 0)
        m = int(counts.get("medium", 0) or 0)
        lo = int(counts.get("low", 0) or 0)
        tot = int(meta.get("total", 0) or 0)
        sec = int(meta.get("secrets_total", 0) or 0)
        app["last_scan"]     = _now()
        app["last_mode"]     = meta.get("mode", "")
        app["vuln_critical"] = c
        app["vuln_high"]     = h
        app["vuln_medium"]   = m
        app["vuln_low"]      = lo
        app["vuln_total"]    = tot
        app["secrets_total"] = sec
        app["risk_tier"]     = _risk_tier(c, h, m, lo)
        app.setdefault("scan_history", []).append({
            "ts":       app["last_scan"],
            "mode":     app["last_mode"],
            "critical": c, "high": h,
            "medium":   m, "low":  lo,
            "total":    tot,
        })
        # Keep last 50 scans in history
        app["scan_history"] = app["scan_history"][-50:]
        self.save_app(app)


# ─────────────────────────────────────────────────────────────────────────────
# UI helpers (palette-aware, re-uses ScannerApp conventions)
# ─────────────────────────────────────────────────────────────────────────────

def _T() -> dict:
    """Return the live palette dict from the main module (already imported by the time this is called)."""
    import sys
    gui = sys.modules.get("Snyk_Scanner_GUI") or sys.modules.get("__main__")
    if gui is not None:
        t = getattr(gui, "T", None)
        if t is not None:
            return t
    # Fallback: attempt a normal import (works after the module is initialised)
    try:
        import Snyk_Scanner_GUI as _gui  # noqa: PLC0415
        return _gui.T
    except Exception:
        pass
    # Last resort: light-mode defaults so the UI is at least readable
    return {
        "bg": "#f5f6f8", "panel_bg": "#ffffff", "surface2": "#eef1f7",
        "accent": "#F5A800", "accent_hi": "#c48700", "button_fg": "#ffffff",
        "accent2": "#c8102e", "accent2_hi": "#a00d24",
        "text": "#0d1b2a", "muted": "#5a6475", "border": "#dde2ec",
        "ok": "#1a7a4a", "err": "#c8102e", "card_hover": "#eef1f7",
    }


def _FUI() -> str:
    import sys
    gui = sys.modules.get("Snyk_Scanner_GUI") or sys.modules.get("__main__")
    v = getattr(gui, "_FUI", None) if gui else None
    if v: return v
    try:
        import Snyk_Scanner_GUI as _gui  # noqa: PLC0415
        return _gui._FUI
    except Exception:
        return "Segoe UI"


def _FMONO() -> str:
    import sys
    gui = sys.modules.get("Snyk_Scanner_GUI") or sys.modules.get("__main__")
    v = getattr(gui, "_FMONO", None) if gui else None
    if v: return v
    try:
        import Snyk_Scanner_GUI as _gui  # noqa: PLC0415
        return _gui._FMONO
    except Exception:
        return "Cascadia Mono"

def _center_over_main(master, win, w_pct=0.65, h_pct=0.80) -> None:
    master.update_idletasks()
    ax, ay = master.winfo_rootx(), master.winfo_rooty()
    aw, ah = master.winfo_width(), master.winfo_height()
    w, h = int(aw * w_pct), int(ah * h_pct)
    win.geometry(f"{w}x{h}+{ax + (aw - w)//2}+{ay + (ah - h)//2}")


# ─────────────────────────────────────────────────────────────────────────────
# App Profile Editor popup
# ─────────────────────────────────────────────────────────────────────────────

class AppProfileEditor(tk.Toplevel):
    """
    Modal dialog to create or edit an application profile.
    Returns the saved app dict (or None if cancelled) via .result attribute.

    geometry_master: ventana usada para calcular tamaño/posición (0.75 × 0.75
    relativo a ésta).  Si se omite, se usa ``master``.  Úsalo cuando el parent
    Tk real es un popup pequeño (ej. el wizard) pero quieres el tamaño de la
    ventana principal.
    """
    def __init__(self, master, store: AppInventoryStore,
                 app: Optional[dict] = None, *,
                 geometry_master=None):
        super().__init__(master)
        self._store  = store
        self._app    = dict(_EMPTY_APP)
        if app:
            self._app.update(app)
        self.result: Optional[dict] = None
        T = _T(); FUI = _FUI()
        _geo_master = geometry_master if geometry_master is not None else master

        self.transient(master)
        _center_over_main(_geo_master, self, 0.75, 0.75)
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.configure(bg=T["accent"])   # amber border frame

        def _close():
            try: self.grab_release()
            except Exception: pass
            self.destroy()
            try: master.focus_force()
            except Exception: pass

        self.bind("<Escape>", lambda _: _close())

        # Amber border shell
        shell = tk.Frame(self, bg=T["accent"], padx=2, pady=2)
        shell.pack(fill="both", expand=True)
        content = tk.Frame(shell, bg=T["bg"])
        content.pack(fill="both", expand=True)
        content.close = _close

        # ── Header ────────────────────────────────────────────────────────────
        hdr_bg = T["panel_bg"]
        hdr = tk.Frame(content, bg=hdr_bg, padx=28, pady=14)
        hdr.pack(fill="x")
        title_text = ("✏  Editar Perfil de Aplicación"
                      if app else "➕  Nueva Aplicación")
        tk.Label(hdr, text=title_text, font=(FUI, 14, "bold"),
                 bg=hdr_bg, fg=T["accent"]).pack(side="left")
        tk.Label(hdr, text="Complete los campos — solo el Nombre es obligatorio.",
                 font=(FUI, 10), bg=hdr_bg, fg=T["muted"]).pack(side="left", padx=(14, 0))
        tk.Frame(content, bg=T["border"], height=1).pack(fill="x")

        # ── Scrollable body ───────────────────────────────────────────────────
        canvas = tk.Canvas(content, bg=T["bg"], highlightthickness=0, bd=0)
        vsb    = ttk.Scrollbar(content, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        holder = tk.Frame(canvas, bg=T["bg"])
        win_id = canvas.create_window((0, 0), window=holder, anchor="nw")
        holder.bind("<Configure>",
                    lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfigure(win_id, width=e.width))
        def _wheel(e): canvas.yview_scroll(int(-e.delta / 120), "units")
        canvas.bind("<Enter>", lambda _: canvas.bind_all("<MouseWheel>", _wheel))
        canvas.bind("<Leave>", lambda _: canvas.unbind_all("<MouseWheel>"))
        pad = tk.Frame(holder, bg=T["bg"], padx=28, pady=16)
        pad.pack(fill="both", expand=True)

        # ── tk.Vars ───────────────────────────────────────────────────────────
        self._vars: dict[str, tk.Variable] = {}

        def sv(key, default=""): v=tk.StringVar(value=self._app.get(key,default)); self._vars[key]=v; return v
        def bv(key, default=False): v=tk.BooleanVar(value=bool(self._app.get(key,default))); self._vars[key]=v; return v

        v_name       = sv("name")
        v_desc       = sv("description")
        v_owner      = sv("owner")
        v_email      = sv("owner_email")
        v_repo       = sv("repo_url")
        v_type       = sv("app_type",       _APP_TYPES[0])
        v_stack      = sv("tech_stack",     _TECH_STACKS[0])
        v_env        = sv("environment",    _ENVIRONMENTS[0])
        v_crit       = sv("criticality",    _CRITICALITY_LEVELS[1])
        v_data       = sv("data_class",     _DATA_CLASSIFICATION[0])



        # ── Section builder helpers ───────────────────────────────────────────
        def section(title: str) -> tk.Frame:
            sh = tk.Frame(pad, bg=T["accent"], padx=12, pady=5)
            sh.pack(fill="x", pady=(12, 6))
            tk.Label(sh, text=title, font=(FUI, 10, "bold"),
                     bg=T["accent"], fg=T["button_fg"]).pack(side="left")
            inner = tk.Frame(pad, bg=T["panel_bg"],
                             highlightthickness=1,
                             highlightbackground=T["border"])
            inner.pack(fill="x", pady=(0, 4))
            body_f = tk.Frame(inner, bg=T["panel_bg"], padx=14, pady=10)
            body_f.pack(fill="both", expand=True)
            return body_f

        def row(parent, label: str, widget_factory, tip: str = "") -> tk.Widget:
            r = tk.Frame(parent, bg=T["panel_bg"])
            r.pack(fill="x", pady=3)
            lbl = tk.Label(r, text=label, font=(FUI, 10), bg=T["panel_bg"],
                           fg=T["muted"], anchor="w", width=22)
            lbl.pack(side="left")
            w = widget_factory(r)
            w.pack(side="left", fill="x", expand=True)
            return w

        def entry(parent, var) -> ttk.Entry:
            return ttk.Entry(parent, textvariable=var)

        def combo(parent, var, values) -> ttk.Combobox:
            return ttk.Combobox(parent, textvariable=var,
                                values=values, state="readonly", width=36)

        # ── Section: Identity ─────────────────────────────────────────────────
        s1 = section("🏷  IDENTIDAD")

        # Application Name: searchable list from the bank's app catalog,
        # with a free-text fallback for apps not yet in the catalog.
        _BANK_APPS = [
            "ACL Analytics", "Activación", "AllianceWarehouse", "ALPINEDEVSECOPSNODE2",
            "API Manager", "auth-service", "Avaya Acra Report", "axiscom",
            "B2B_Loans", "B3", "Backoffice - AML", "BackOffice - Captacion",
            "Backoffice - Catalogs", "Backoffice - Client as a Service",
            "Backoffice - Digital Business", "Backoffice - Framework",
            "Backoffice - Middle Office", "Backoffice - Operations",
            "Backoffice - Security", "BackOffice - Solutions", "Bajaware",
            "Base Fix API", "Baseinet", "Baseinet - Automation", "BaseLake",
            "BaseMX", "Bastian", "BaseWEB - Refresh", "Bayu", "BI",
            "Binnacle App", "Biometrics", "Blacklist Api", "bloom", "BPM",
            "Calculator", "ChannelPayments", "CI/CD", "CIS BenchMark", "Citrix",
            "Clients API", "Cloud", "Cognos", "Collectpayments",
            "CommonLibraries-dso", "commons-dev", "Communicator", "ConnectDirect",
            "Constancias - Retenciones", "Contabilidad", "ContPaq",
            "ContratoDigitalExp", "Core Batch", "Core FX", "Core Withholding",
            "coreaxis", "Corems", "Credit Bureau", "Crypto API", "Customers",
            "Darwin", "DataHub", "Datascience", "DealTracker", "DevelopTools",
            "devsecops-alpine-python-1", "devsecops-ex-py-1",
            "devsecops-workshop-sample-1", "DEVSECOPSALPINEJAVA1",
            "Digital infrastructure", "Digital Transformation", "DirectDebit",
            "Easycredit", "ESB", "ESBs", "Fiel Services", "FinantialOCI",
            "FixReader", "FoundDispersion", "generic",
            "gfb-devsecops-infra-onprem-cloud", "gfb-externalpayments", "GWDB",
            "H2H", "Historical Databases", "Hopex", "Image check", "Imperva",
            "indeval", "Infrastructure Requests POC", "Infrastrucutre Requests",
            "Instrumental", "Intelexion", "Interfaz BBASE Creditos",
            "Interfaz Reuters", "InvoiceAssignment", "ISILoans", "IT Architecture",
            "ITAL", "Kondor - Derivatives", "Legal", "Lexis Nexis - AML",
            "maincatalogs", "MessageHub", "ModeloRiesgo", "MoneyMarketBk",
            "MoneyMarketCB", "Nautilus", "Notificator API", "Nuba2.0", "OnBase",
            "Onboarding", "Onboarding-Gen", "Onboarding-PF", "Onboarding-PM",
            "Pagare", "Panjiva", "PIPELINE-BPM", "PLD", "PLD - Fraudes",
            "Power BI", "Price Vector", "PrivateCloud", "PROKEY1", "Proleasenet",
            "Quadient", "RecipientAccounts", "Release Management", "Rentabilidad",
            "RiskAnalysis", "RPA", "Sailpoint", "Salesforce", "SatEnrichment",
            "security", "Service Now", "Sibase", "Siglo", "Siscore", "SonarQube",
            "specoff", "SPEI", "SPID", "SWA", "SWIFT", "Tableau", "Taller Git",
            "Teller", "Transactional-linking", "Validanet", "Veritran VTET",
            "Volpay", "WebLandings", "WinService Alerts", "wiretransfer",
            "workflowcontroller", "Workspaces", "Wrapper", "Wso2_internal",
        ]

        # Name row: search box + listbox side by side
        name_outer = tk.Frame(s1, bg=T["panel_bg"]); name_outer.pack(fill="x", pady=3)
        tk.Label(name_outer, text="Nombre de la Aplicación *", font=(FUI, 10),
                 bg=T["panel_bg"], fg=T["muted"], anchor="w", width=22).pack(side="left")
        name_right = tk.Frame(name_outer, bg=T["panel_bg"]); name_right.pack(side="left", fill="x", expand=True)

        # Search / filter entry
        search_var = tk.StringVar()
        search_entry = ttk.Entry(name_right, textvariable=search_var)
        search_entry.pack(fill="x")

        # Listbox with scrollbar
        lb_wrap = tk.Frame(name_right, bg=T["panel_bg"],
                           highlightthickness=1, highlightbackground=T["border"])
        lb_wrap.pack(fill="x", pady=(2, 0))
        app_lb = tk.Listbox(lb_wrap, height=5, font=(FUI, 10),
                            bg=T["surface2"], fg=T["text"],
                            selectbackground=T["accent"], selectforeground=T["button_fg"],
                            activestyle="none", relief="flat",
                            highlightthickness=0, exportselection=False)
        lb_sb = ttk.Scrollbar(lb_wrap, orient="vertical", command=app_lb.yview)
        app_lb.configure(yscrollcommand=lb_sb.set)
        app_lb.pack(side="left", fill="x", expand=True)
        lb_sb.pack(side="right", fill="y")

        hint_lbl = tk.Label(name_right,
                            text="Escribe para filtrar · selecciona para usar · o escribe un nombre nuevo",
                            font=(FUI, 9), bg=T["panel_bg"], fg=T["muted"])
        hint_lbl.pack(anchor="w", pady=(2, 0))

        # Merge catalog + any apps already saved in the store (custom names)
        _stored_names = [a["name"] for a in self._store.list_apps() if a.get("name")]
        _all_names = sorted(
            set(_BANK_APPS) | set(_stored_names),
            key=lambda s: s.lower(),
        )

        def _populate_lb(filter_text=""):
            app_lb.delete(0, "end")
            ft = filter_text.strip().lower()
            for name in _all_names:
                if ft in name.lower():
                    app_lb.insert("end", name)
            # Highlight current value if it's in the list
            cur = v_name.get().strip()
            for i in range(app_lb.size()):
                if app_lb.get(i) == cur:
                    app_lb.selection_set(i); app_lb.see(i); break

        _populate_lb()

        def _sync_name_from_entry(*_):
            """Called on every keystroke: filter the list AND keep v_name in sync.
            If the typed text matches a catalog entry exactly, select it in the
            listbox; otherwise v_name holds whatever free text the user typed."""
            txt = search_var.get()
            v_name.set(txt.strip())
            _populate_lb(txt)
            # Highlight an exact catalog match if present
            for i in range(app_lb.size()):
                if app_lb.get(i).lower() == txt.strip().lower():
                    app_lb.selection_clear(0, "end")
                    app_lb.selection_set(i)
                    app_lb.see(i)
                    break
            else:
                # No exact match — clear any stale listbox selection so the
                # free-text value in v_name is unambiguously what will be saved.
                app_lb.selection_clear(0, "end")

        def _on_lb_select(evt=None):
            sel = app_lb.curselection()
            if sel:
                chosen = app_lb.get(sel[0])
                v_name.set(chosen)
                # Pause trace briefly to avoid re-triggering _sync_name_from_entry
                search_var.trace_remove("write", _search_trace_id[0])
                search_var.set(chosen)
                _search_trace_id[0] = search_var.trace_add("write", _sync_name_from_entry)

        _search_trace_id = [search_var.trace_add("write", _sync_name_from_entry)]
        app_lb.bind("<<ListboxSelect>>", _on_lb_select)
        app_lb.bind("<Double-1>", _on_lb_select)
        # Enter on the search entry confirms the typed name without requiring a
        # listbox click — useful for free-text names not in the catalog.
        search_entry.bind("<Return>", lambda _: self.focus_set())

        # Pre-fill search entry with existing app name (edit mode)
        if self._app.get("name"):
            search_var.set(self._app["name"])
            _populate_lb(self._app["name"])

        row(s1, "Descripción",          lambda p: entry(p, v_desc))
        row(s1, "Responsable / Equipo", lambda p: entry(p, v_owner))
        row(s1, "Correo del responsable", lambda p: entry(p, v_email))
        row(s1, "URL del repositorio",   lambda p: entry(p, v_repo))

        # ── Section: Classification ───────────────────────────────────────────
        s2 = section("🔖  CLASIFICACIÓN")
        row(s2, "Tipo de Aplicación",   lambda p: combo(p, v_type,  _APP_TYPES))
        row(s2, "Stack Tecnológico",    lambda p: combo(p, v_stack, _TECH_STACKS))
        row(s2, "Entorno",              lambda p: combo(p, v_env,   _ENVIRONMENTS))
        row(s2, "Criticidad de Negocio", lambda p: combo(p, v_crit, _CRITICALITY_LEVELS))
        row(s2, "Clasificación de Datos", lambda p: combo(p, v_data, _DATA_CLASSIFICATION))



        # ── Footer ────────────────────────────────────────────────────────────
        tk.Frame(content, bg=T["border"], height=1).pack(fill="x")
        foot = tk.Frame(content, bg=T["panel_bg"], padx=24, pady=12)
        foot.pack(fill="x")
        self._status_lbl = tk.Label(foot, text="", font=(FUI, 10),
                                    bg=T["panel_bg"], fg=T["err"])
        self._status_lbl.pack(side="left")

        def _save():
            # v_name is kept in sync with search_var by _sync_name_from_entry;
            # fall back to search_var directly as belt-and-suspenders.
            name = v_name.get().strip() or search_var.get().strip()
            if not name:
                self._status_lbl.config(text="⚠  El Nombre de la Aplicación es obligatorio.")
                return
            a = dict(self._app)
            a["name"]         = name
            a["description"]  = v_desc.get().strip()
            a["owner"]        = v_owner.get().strip()
            a["owner_email"]  = v_email.get().strip()
            a["repo_url"]     = v_repo.get().strip()
            a["app_type"]     = v_type.get()
            a["tech_stack"]   = v_stack.get()
            a["environment"]  = v_env.get()
            a["criticality"]  = v_crit.get()
            a["data_class"]   = v_data.get()
            if not a.get("id"):
                a["id"] = _slugify(name)
            self._store.save_app(a)
            self.result = a
            _close()

        for txt, cmd, bg_key, hi_key in [
            ("Cancelar",          _close, "surface2", "card_hover"),
            ("💾  Guardar Perfil", _save,  "accent",   "accent_hi"),
        ]:
            tk.Button(foot, text=txt, command=cmd,
                      bg=T[bg_key], fg=T["button_fg"] if bg_key=="accent" else T["text"],
                      activebackground=T[hi_key],
                      activeforeground=T["button_fg"] if bg_key=="accent" else T["accent"],
                      font=(FUI, 11, "bold"), relief="flat",
                      padx=14, pady=6, cursor="hand2").pack(side="right", padx=(6, 0))

        try: self.grab_set()
        except tk.TclError: pass
        self.focus_force()


# ─────────────────────────────────────────────────────────────────────────────
# App Inventory Tab  (embedded directly into ScannerApp body stack)
# ─────────────────────────────────────────────────────────────────────────────

class AppInventoryTab:
    

    def __init__(self, parent: tk.Frame, master: tk.Tk,
                 store: AppInventoryStore,
                 on_load_app=None):
        self._parent       = parent
        self._master       = master
        self._store        = store
        self._on_load_app  = on_load_app
        self._current_app: Optional[dict] = None
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        T = _T(); FUI = _FUI()

        # Section header
        hdr = tk.Frame(self._parent, bg=T["panel_bg"], padx=18, pady=8,
                       highlightthickness=1, highlightbackground=T["border"])
        hdr.pack(fill="x")
        self._title_lbl = tk.Label(hdr, text="📦  Inventario de Aplicaciones",
                 font=(FUI, 13, "bold"), bg=T["panel_bg"],
                 fg=T["accent"])
        self._title_lbl.pack(side="left")
        self._title_app_lbl = tk.Label(hdr, text="",
                 font=(FUI, 13, "bold"), bg=T["panel_bg"],
                 fg=T["text"])
        self._title_app_lbl.pack(side="left")

        # ── Toolbar ───────────────────────────────────────────────────────────
        # Everything that used to live in three stacked rows (stats strip,
        # action buttons, search field) now shares a single row so the table
        # below gets the vertical space back. Dashboard tiles are kept
        # compact (number + label side-by-side) specifically so they leave
        # room for the buttons/search/active-app cluster on the same line.
        toolbar = tk.Frame(self._parent, bg=T["bg"], padx=18, pady=8)
        toolbar.pack(fill="x")

        def _vsep():
            tk.Frame(toolbar, bg=T["border"], width=1).pack(
                side="left", fill="y", padx=10, pady=2)

        self._build_dashboard(toolbar)
        _vsep()

        # Load into Scanner — uses 📂 to distinguish from the ▶ run-scan button
        self._load_btn = tk.Button(
            toolbar, text="📂  Cargar", command=self._load_into_scanner,
            bg=T["accent2"], fg=T["button_fg"],
            activebackground="#a00d24", activeforeground=T["button_fg"],
            font=(FUI, 11, "bold"), relief="flat",
            padx=12, pady=5, cursor="hand2")
        self._load_btn.pack(side="left", padx=(0, 6))

        for txt, cmd, bg, hi in [
            ("+ Nueva", self._new_app,    T["accent"],   T["accent_hi"]),
            ("✏",        self._edit_app,   T["surface2"], T["card_hover"]),
            ("🗑",        self._delete_app, T["surface2"], T["card_hover"]),
        ]:
            fg = T["button_fg"] if bg == T["accent"] else T["text"]
            b = tk.Button(toolbar, text=txt, command=cmd,
                          bg=bg, fg=fg,
                          activebackground=hi, activeforeground=fg,
                          font=(FUI, 11, "bold"), relief="flat",
                          padx=12, pady=5, cursor="hand2")
            b.pack(side="left", padx=(0, 6))

        # ── Search / filter — placeholder text lives inside the field itself
        # (no more separate "filter by..." label) and disappears once the
        # field gets focus / real input.
        search_frame = tk.Frame(toolbar, bg=T["bg"])
        search_frame.pack(side="left", fill="x", expand=True)
        tk.Label(search_frame, text="🔎", font=(FUI, 11), bg=T["bg"], fg=T["muted"]).pack(side="left")

        SEARCH_PLACEHOLDER = "filtrar por nombre, tipo, entorno o nivel de riesgo"
        self._search_var = tk.StringVar(value=SEARCH_PLACEHOLDER)
        self._search_showing_placeholder = True
        search_entry = ttk.Entry(search_frame, textvariable=self._search_var,
                                  foreground=T["muted"])
        search_entry.pack(side="left", padx=(6, 0), fill="x", expand=True)

        def _clear_placeholder(_e=None):
            if self._search_showing_placeholder:
                self._search_showing_placeholder = False
                self._search_var.set("")
                search_entry.configure(foreground=T["text"])

        def _restore_placeholder(_e=None):
            if not self._search_var.get():
                self._search_showing_placeholder = True
                self._search_var.set(SEARCH_PLACEHOLDER)
                search_entry.configure(foreground=T["muted"])

        search_entry.bind("<FocusIn>", _clear_placeholder)
        search_entry.bind("<FocusOut>", _restore_placeholder)
        self._search_var.trace_add("write", lambda *_: self.refresh())

        # ── Main split: table (left) + detail panel (right) ──────────────────
        split = tk.Frame(self._parent, bg=T["bg"])
        split.pack(fill="both", expand=True, padx=18, pady=(0, 12))

        # Left: inventory treeview
        left = tk.Frame(split, bg=T["panel_bg"],
                        highlightthickness=1, highlightbackground=T["border"])
        left.pack(side="left", fill="both", expand=True)

        tree_hdr = tk.Frame(left, bg=T["accent"], padx=12, pady=5)
        tree_hdr.pack(fill="x")
        tk.Label(tree_hdr, text="REGISTRO DE APLICACIONES",
                 font=(FUI, 10, "bold"), bg=T["accent"],
                 fg=T["button_fg"]).pack(side="left")

        cols = ("name","type","env","crit","vulns","risk","last_scan")
        self._tree = ttk.Treeview(left, columns=cols,
                                  show="headings", height=22)
        headings = [
            ("name",      "Aplicación",        200),
            ("type",      "Tipo",              120),
            ("env",       "Entorno",            90),
            ("crit",      "Criticidad",        110),
            ("vulns",     "🐛 C / A / M / B",  140),
            ("risk",      "Nivel de Riesgo",    90),
            ("last_scan", "Último Escaneo",    130),
        ]
        for col, txt, width in headings:
            self._tree.heading(col, text=txt,
                               command=lambda c=col: self._sort_by(c))
            self._tree.column(col, width=width, anchor="w")


        vsb = ttk.Scrollbar(left, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        self._tree.bind("<Double-1>", lambda _: self._edit_app())

        # Right: detail panel
        right = tk.Frame(split, bg=T["panel_bg"],
                         highlightthickness=1, highlightbackground=T["border"])
        right.pack(side="right", fill="y", padx=(8, 0))
        right.configure(width=300)
        right.pack_propagate(False)

        detail_hdr = tk.Frame(right, bg=T["accent"], padx=12, pady=5)
        detail_hdr.pack(fill="x")
        tk.Label(detail_hdr, text="DETALLES DE APLICACIÓN",
                 font=(FUI, 10, "bold"), bg=T["accent"],
                 fg=T["button_fg"]).pack(side="left")

        self._detail_canvas = tk.Canvas(right, bg=T["panel_bg"],
                                        highlightthickness=0, bd=0)
        detail_vsb = ttk.Scrollbar(right, orient="vertical",
                                   command=self._detail_canvas.yview)
        self._detail_canvas.configure(yscrollcommand=detail_vsb.set)
        self._detail_canvas.pack(side="left", fill="both", expand=True)
        detail_vsb.pack(side="right", fill="y")
        self._detail_frame = tk.Frame(self._detail_canvas, bg=T["panel_bg"])
        self._detail_win   = self._detail_canvas.create_window(
            (0, 0), window=self._detail_frame, anchor="nw")
        self._detail_frame.bind(
            "<Configure>",
            lambda _: self._detail_canvas.configure(
                scrollregion=self._detail_canvas.bbox("all")))
        self._detail_canvas.bind(
            "<Configure>",
            lambda e: self._detail_canvas.itemconfigure(
                self._detail_win, width=e.width))

        self._show_detail(None)
        self.refresh()

    # ── Inventory tree population ─────────────────────────────────────────────

    # ── Portfolio dashboard ────────────────────────────────────────────────────
    def _build_dashboard(self, parent):
        """One-row strip of portfolio-wide tiles: total apps, aggregate
        findings by severity across every app's last scan, and how many
        apps haven't been scanned in the last 30 days. This is the 'all
        apps, total risk, trend' view that a per-app detail panel can't
        give you — meant for status updates / Subdirección conversations
        rather than day-to-day per-app work."""
        T = _T(); FUI = _FUI()
        self._dash_tiles: dict[str, dict] = {}
        specs = [
            ("apps",     "Apps registradas",  T["text"]),
            ("critical", "🔴 Crítico",         _RISK_COLORS_LIGHT["Crítico"]),
            ("high",     "🟠 Alto",            _RISK_COLORS_LIGHT["Alto"]),
            ("medium",   "🟡 Medio",           _RISK_COLORS_LIGHT["Medio"]),
            ("low",      "🟢 Bajo",            _RISK_COLORS_LIGHT["Bajo"]),
            ("stale",    "⏰ Sin escaneo 30d+", T["muted"]),
        ]
        # Compact, single-line tiles (number + label side-by-side, thin top
        # accent bar) — these now share a row with the toolbar buttons and
        # search field, so the old stacked/tall card layout no longer fits.
        for key, label, colour in specs:
            tile = tk.Frame(parent, bg=T["panel_bg"], highlightthickness=1,
                            highlightbackground=T["border"], padx=10, pady=4)
            tile.pack(side="left", fill="y", padx=(0, 6))
            top = tk.Frame(tile, bg=colour, height=2); top.pack(fill="x", pady=(0, 3))
            row = tk.Frame(tile, bg=T["panel_bg"]); row.pack(anchor="w")
            val_lbl = tk.Label(row, text="—", font=(FUI, 15, "bold"), bg=T["panel_bg"], fg=colour)
            val_lbl.pack(side="left")
            tk.Label(row, text=label, font=(FUI, 8), bg=T["panel_bg"], fg=T["muted"]).pack(side="left", padx=(5, 0))
            self._dash_tiles[key] = {"value": val_lbl, "frame": tile, "colour": colour}

    def _refresh_dashboard(self):
        if not hasattr(self, "_dash_tiles"):
            return
        apps = self._store.list_apps()
        agg = {"apps": len(apps), "critical": 0, "high": 0, "medium": 0, "low": 0, "stale": 0}
        cutoff = datetime.now() - timedelta(days=30)
        for app in apps:
            agg["critical"] += int(app.get("vuln_critical", 0) or 0)
            agg["high"]     += int(app.get("vuln_high", 0) or 0)
            agg["medium"]   += int(app.get("vuln_medium", 0) or 0)
            agg["low"]      += int(app.get("vuln_low", 0) or 0)
            last = app.get("last_scan")
            is_stale = True
            if last:
                try:
                    ts = datetime.fromisoformat(str(last)[:19])
                    is_stale = ts < cutoff
                except Exception:
                    is_stale = False  # unparseable timestamp — don't falsely flag as stale
            if is_stale:
                agg["stale"] += 1
        for key, tile in self._dash_tiles.items():
            tile["value"].config(text=str(agg.get(key, 0)))

    def refresh(self):
        self._refresh_dashboard()
        dark = getattr(self._master, "_dark_mode", False)
        risk_colors = _RISK_COLORS_DARK if dark else _RISK_COLORS_LIGHT
        FUI = _FUI()
        for tier, colour in risk_colors.items():
            self._tree.tag_configure(
                tier.lower(), foreground=colour,
                font=(FUI, 11, "bold") if tier in ("Crítico", "Alto") else (FUI, 11))
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        apps = self._store.list_apps()
        if getattr(self, "_search_showing_placeholder", False):
            needle = ""
        else:
            needle = (getattr(self, "_search_var", None) and self._search_var.get() or "").strip().lower()
        if needle:
            apps = [a for a in apps if needle in " ".join(str(a.get(k, "")) for k in
                    ("name", "app_type", "environment", "risk_tier", "criticality")).lower()]
        for app in apps:
            vulns = (f"{app.get('vuln_critical',0)} / "
                     f"{app.get('vuln_high',0)} / "
                     f"{app.get('vuln_medium',0)} / "
                     f"{app.get('vuln_low',0)}")
            last  = app.get("last_scan") or "—"
            tier  = app.get("risk_tier", "Ninguno")
            self._tree.insert(
                "", "end", iid=app["id"],
                values=(
                    app.get("name",""),
                    app.get("app_type",""),
                    app.get("environment",""),
                    app.get("criticality",""),
                    vulns,
                    tier,
                    last[:16] if last != "—" else "—",
                ),
                tags=(tier.lower(),),
            )
        # Re-select active if exists
        if self._current_app:
            aid = self._current_app.get("id","")
            if self._tree.exists(aid):
                self._tree.selection_set(aid)
                self._tree.see(aid)

    def _sort_by(self, col: str):
        """Toggle-sort treeview by column."""
        items = [(self._tree.set(iid, col), iid)
                 for iid in self._tree.get_children()]
        rev = getattr(self, f"_sort_rev_{col}", False)
        items.sort(reverse=rev,
                   key=lambda x: x[0].lower() if x[0] else "")
        for idx, (_, iid) in enumerate(items):
            self._tree.move(iid, "", idx)
        setattr(self, f"_sort_rev_{col}", not rev)

    # ── Detail panel ──────────────────────────────────────────────────────────

    def _show_detail(self, app: Optional[dict]):
        T = _T(); FUI = _FUI()
        self._detail_canvas.configure(bg=T["panel_bg"])
        self._detail_frame.configure(bg=T["panel_bg"])
        for w in self._detail_frame.winfo_children():
            w.destroy()

        if app is None:
            tk.Label(self._detail_frame,
                     text="Selecciona una app\nde la lista.",
                     font=(FUI, 11), bg=T["panel_bg"],
                     fg=T["muted"], justify="center").pack(
                expand=True, pady=40)
            return

        pad = tk.Frame(self._detail_frame, bg=T["panel_bg"], padx=14, pady=12)
        pad.pack(fill="both", expand=True)

        def kv(label: str, value: str, bold: bool = False, color=None):
            r = tk.Frame(pad, bg=T["panel_bg"]); r.pack(fill="x", pady=2)
            tk.Label(r, text=label, font=(FUI, 9, "bold"),
                     bg=T["panel_bg"], fg=T["muted"],
                     anchor="w", width=18).pack(side="left")
            tk.Label(r, text=value or "—",
                     font=(FUI, 10, "bold" if bold else "normal"),
                     bg=T["panel_bg"],
                     fg=color or T["text"],
                     anchor="w", wraplength=180,
                     justify="left").pack(side="left")

        tier  = app.get("risk_tier", "Ninguno")
        tc    = (_RISK_COLORS_DARK if getattr(self._master, "_dark_mode", False) else _RISK_COLORS_LIGHT).get(tier, T["muted"])
        kv("Nombre",       app.get("name",""),       bold=True)
        kv("Nivel de Riesgo", tier,                  bold=True, color=tc)
        kv("Tipo",         app.get("app_type",""))
        kv("Stack",        app.get("tech_stack",""))
        kv("Entorno",      app.get("environment",""))
        kv("Criticidad",   app.get("criticality",""))
        kv("Clasif. Datos", app.get("data_class",""))

        tk.Frame(pad, bg=T["border"], height=1).pack(fill="x", pady=8)

        # Vulnerability badge row
        c = app.get("vuln_critical",0)
        h = app.get("vuln_high",0)
        m = app.get("vuln_medium",0)
        lo = app.get("vuln_low",0)
        tot = app.get("vuln_total", c+h+m+lo)

        badge_row = tk.Frame(pad, bg=T["panel_bg"]); badge_row.pack(fill="x")
        for count, label, bg_hex in [
            (c,  "Crítico", "#7a0c1c"),
            (h,  "Alto",     "#8b3a0a"),
            (m,  "Medio",   "#7a5e00"),
            (lo, "Bajo",      "#0c4a2b"),
        ]:
            badge = tk.Frame(badge_row, bg=bg_hex,
                             padx=6, pady=4)
            badge.pack(side="left", padx=(0, 4))
            tk.Label(badge, text=str(count), font=(FUI, 12, "bold"),
                     bg=bg_hex, fg="#ffffff").pack()
            tk.Label(badge, text=label, font=(FUI, 8),
                     bg=bg_hex, fg="#cccccc").pack()

        kv("Total Vulns",   str(tot))
        kv("Secretos",      str(app.get("secrets_total",0)))
        kv("Último Escaneo", (app.get("last_scan") or "—")[:16])
        kv("Modo",          app.get("last_mode","—"))

        tk.Frame(pad, bg=T["border"], height=1).pack(fill="x", pady=8)

        kv("Responsable",      app.get("owner",""))
        kv("Email",      app.get("owner_email",""))
        kv("Objetivo",     app.get("target_path","")[-40:] if app.get("target_path") else "—")
        kv("URL para DAST",   app.get("dast_url",""))

        comp = app.get("compliance",[])
        if comp:
            tk.Frame(pad, bg=T["border"], height=1).pack(fill="x", pady=8)
            tk.Label(pad, text="COMPLIANCE",
                     font=(FUI, 9, "bold"), bg=T["panel_bg"],
                     fg=T["muted"], anchor="w").pack(fill="x")
            tk.Label(pad, text=", ".join(comp),
                     font=(FUI, 9), bg=T["panel_bg"],
                     fg=T["text"], anchor="w",
                     wraplength=240, justify="left").pack(fill="x")

        notes = app.get("notes","")
        if notes:
            tk.Frame(pad, bg=T["border"], height=1).pack(fill="x", pady=8)
            tk.Label(pad, text="NOTAS",
                     font=(FUI, 9, "bold"), bg=T["panel_bg"],
                     fg=T["muted"], anchor="w").pack(fill="x")
            tk.Label(pad, text=notes,
                     font=(FUI, 9), bg=T["panel_bg"],
                     fg=T["text"], anchor="w",
                     wraplength=240, justify="left").pack(fill="x")

        # Scan history mini-chart
        history = app.get("scan_history", [])
        if len(history) >= 2:
            self._draw_trend(pad, history, T, FUI)

    def _draw_trend(self, parent, history: list, T: dict, FUI: str):
        """Draw a tiny SVG-style canvas trend chart of the last N scans."""
        tk.Frame(parent, bg=T["border"], height=1).pack(fill="x", pady=8)
        tk.Label(parent, text="TENDENCIA DE VULNERABILIDADES (últimos escaneos)",
                 font=(FUI, 9, "bold"), bg=T["panel_bg"],
                 fg=T["muted"], anchor="w").pack(fill="x")

        W, H = 260, 90
        cv = tk.Canvas(parent, width=W, height=H,
                       bg=T["surface2"], bd=0, highlightthickness=0)
        cv.pack(pady=(4, 0))

        entries = history[-10:]
        n = len(entries)
        max_v  = max((e.get("total", 0) or 0) for e in entries) or 1
        xs = [int(12 + (i / max(n-1, 1)) * (W - 24)) for i in range(n)]

        def y_for(v): return int(H - 8 - (v / max_v) * (H - 20))

        # Grid lines
        for pct in (0.25, 0.5, 0.75, 1.0):
            yy = y_for(int(max_v * pct))
            cv.create_line(4, yy, W-4, yy, fill=T["border"], dash=(2, 4))

        # Lines per severity
        for key, colour in [
            ("critical", "#c8102e"), ("high", "#e26020"),
            ("medium",   "#d4a017"), ("total",  T["muted"]),
        ]:
            pts = []
            for i, e in enumerate(entries):
                pts += [xs[i], y_for(e.get(key, e.get("total", 0) or 0))]
            if len(pts) >= 4:
                cv.create_line(pts, fill=colour, width=2, smooth=True)

        # Dots for latest
        if entries:
            last = entries[-1]
            for key, colour in [
                ("critical","#c8102e"), ("high","#e26020"),
                ("medium","#d4a017"),
            ]:
                v = last.get(key, 0) or 0
                if v:
                    yy = y_for(v)
                    cv.create_oval(xs[-1]-4, yy-4, xs[-1]+4, yy+4,
                                   fill=colour, outline="")

        # X-axis labels (first and last)
        if entries:
            cv.create_text(xs[0], H-2, text=entries[0].get("ts","")[:10],
                           font=(FUI, 7), fill=T["muted"], anchor="s")
            cv.create_text(xs[-1], H-2, text=entries[-1].get("ts","")[:10],
                           font=(FUI, 7), fill=T["muted"], anchor="s")

    # ── Event handlers ────────────────────────────────────────────────────────

    def _on_select(self, _event=None):
        sel = self._tree.selection()
        if sel:
            app = self._store.get_app(sel[0])
            self._show_detail(app)
        else:
            self._show_detail(None)

    def _selected_app(self) -> Optional[dict]:
        sel = self._tree.selection()
        return self._store.get_app(sel[0]) if sel else None

    def _new_app(self):
        ed = AppProfileEditor(self._master, self._store)
        self._master.wait_window(ed)
        if ed.result:
            self.refresh()
            self._tree.selection_set(ed.result["id"])
            self._show_detail(ed.result)

    def _edit_app(self):
        app = self._selected_app()
        if not app:
            return
        ed = AppProfileEditor(self._master, self._store, app)
        self._master.wait_window(ed)
        if ed.result:
            self.refresh()
            self._show_detail(ed.result)

    def _delete_app(self):
        app = self._selected_app()
        if not app:
            return
        T = _T(); FUI = _FUI()
        win = tk.Toplevel(self._master)
        win.title("Eliminar aplicación")
        win.configure(bg=T["bg"])
        win.transient(self._master)
        _center_over_main(self._master, win, 0.32, 0.18)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        border = tk.Frame(win, bg=T["accent"], padx=2, pady=2)
        border.pack(fill="both", expand=True)
        inner = tk.Frame(border, bg=T["bg"], padx=24, pady=16)
        inner.pack(fill="both", expand=True)
        tk.Label(inner, text=f"¿Eliminar '{app['name']}'?\nEsta acción no se puede deshacer.",
                 font=(FUI, 11), bg=T["bg"], fg=T["text"],
                 justify="center").pack(pady=(0, 14))
        btn_row = tk.Frame(inner, bg=T["bg"]); btn_row.pack()
        def _confirm():
            self._store.delete_app(app["id"])
            if self._current_app and self._current_app.get("id") == app["id"]:
                self._current_app = None
                self._update_title_label(None)
            win.destroy()
            self.refresh()
            self._show_detail(None)
        tk.Button(btn_row, text="Cancelar", command=win.destroy,
                  bg=T["surface2"], fg=T["text"], font=(FUI, 11),
                  relief="flat", padx=10, pady=5, cursor="hand2").pack(side="left", padx=(0, 8))
        tk.Button(btn_row, text="🗑  Eliminar", command=_confirm,
                  bg=T["accent2"], fg=T["button_fg"], font=(FUI, 11, "bold"),
                  relief="flat", padx=10, pady=5, cursor="hand2").pack(side="left")
        try: win.grab_set()
        except Exception: pass

    def _load_into_scanner(self):
        app = self._selected_app()
        if not app:
            return
        self._current_app = app
        T = _T()
        self._update_title_label(app)
        if self._on_load_app:
            self._on_load_app(app)

    # ── Public API called from ScannerApp ─────────────────────────────────────

    def _update_title_label(self, app: "Optional[dict]") -> None:
        """Update the inline active-app portion of the header title."""
        lbl = getattr(self, "_title_app_lbl", None)
        if lbl is None:
            return
        T = _T()
        if app:
            lbl.config(text=f": {app['name']}", fg=T["text"])
        else:
            lbl.config(text="", fg=T["text"])

    def apply_theme(self) -> None:
        """Rebuild the tab UI in-place with the current palette.

        Called by ScannerApp._apply_theme_to_app() after toggling dark/light
        mode.  Because app_inventory widgets are plain tk.* (not ttk.*) and
        were created with colour values at construction time, we must tear
        them down and recreate them so they pick up the new palette.  The
        current selection and active-app state are preserved.
        """
        # Preserve state across the rebuild
        sel = self._tree.selection()
        selected_id  = sel[0] if sel else None
        active_app   = self._current_app

        # Destroy all existing children of the parent frame
        for child in list(self._parent.winfo_children()):
            try:
                child.destroy()
            except Exception:
                pass

        # Rebuild with the now-current palette
        self._build()

        # Restore selection
        if selected_id and self._tree.exists(selected_id):
            self._tree.selection_set(selected_id)
            self._tree.see(selected_id)
            app = self._store.get_app(selected_id)
            self._show_detail(app)

        # Restore active-app label
        if active_app:
            self._current_app = active_app
            self._update_title_label(active_app)
