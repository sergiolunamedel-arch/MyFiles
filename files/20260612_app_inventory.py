"""
app_inventory.py — Application Profile & Inventory System
==========================================================
Manages a portfolio of application profiles ("apps") that each carry their
own scan configuration, target path, DAST/API settings, and cumulative
vulnerability history.

Persistence: one JSON file per app at  <reports_root>/inventory/<slug>.json
Master index: <reports_root>/inventory/_index.json

Designed to be imported by Snyk_Scanner_GUI.py and surfaced as a dedicated
"📦 Apps" tab in the ribbon.

Author: Banco Base SecDevOps / Vulnerability Scanner
Compliance alignment: ISO 27001, OWASP SAMM, NIST CSF, CWE/CVE taxonomy
"""
from __future__ import annotations

import json
import os
import re
import shutil
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

# Risk-tier mapping used in the inventory dashboard
_RISK_COLORS_LIGHT = {
    "Critical": "#c8102e",
    "High":     "#e26020",
    "Medium":   "#d4a017",
    "Low":      "#1a7a4a",
    "None":     "#5a6475",
}
_RISK_COLORS_DARK = {
    "Critical": "#f08090",
    "High":     "#f4a460",
    "Medium":   "#f0d060",
    "Low":      "#5fe0a0",
    "None":     "#8892a4",
}

# Standard technology stack choices (inspired by OWASP SAMM)
_TECH_STACKS = [
    "Python", "Node.js / JavaScript", "Java / Spring", "C# / .NET",
    "Go", "Ruby on Rails", "PHP", "Rust", "C / C++", "Kotlin / Android",
    "Swift / iOS", "React / Vue / Angular (SPA)", "Mobile (React Native)",
    "Microservices", "Serverless / Lambda", "Other",
]

# Deployment environment options
_ENVIRONMENTS = [
    "Production", "Staging / Pre-prod", "QA / Testing",
    "Development", "Internal / Intranet", "Cloud (AWS)", "Cloud (Azure)",
    "Cloud (GCP)", "On-Premise", "Hybrid",
]

# Application type (affects which scan stages make sense)
_APP_TYPES = [
    "Web Application", "REST API", "GraphQL API", "Mobile App (iOS)",
    "Mobile App (Android)", "Desktop Application", "CLI Tool / Script",
    "Microservice", "Data Pipeline", "Batch / Background Job",
    "IoT / Embedded", "Library / SDK", "Other",
]

# Business criticality aligned with ISO 27001 asset classification
_CRITICALITY_LEVELS = [
    "Mission Critical",   # Downtime = revenue loss / regulatory breach
    "Business Critical",  # Core operations affected
    "Important",          # Significant but tolerable impact
    "Standard",           # Normal business function
    "Low",                # Minimal impact if unavailable
]

# Compliance frameworks that may apply
_COMPLIANCE_TAGS = [
    "PCI-DSS", "PCI-DSS v4", "ISO 27001", "ISO 27001:2022",
    "SOC 2 Type II", "NIST CSF", "NIST SP 800-53",
    "OWASP Top-10", "OWASP ASVS", "CIS Benchmarks",
    "GDPR", "LFPDPPP (Mexico)", "CNBV Circular", "DORA (EU)",
    "HIPAA", "FedRAMP", "NOM-151", "None",
]

# Data classification aligned with banking sector standards
_DATA_CLASSIFICATION = [
    "Confidential — Financial",   # Account numbers, balances, transactions
    "Confidential — Personal",    # PII / SPEI / CLABE
    "Restricted",                 # Internal business data
    "Internal",                   # Non-sensitive internal data
    "Public",                     # Marketing / public-facing data
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
    "risk_tier":     "None",       # derived: Critical/High/Medium/Low/None
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
    if critical:  return "Critical"
    if high:      return "High"
    if medium:    return "Medium"
    if low:       return "Low"
    return "None"


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

    def reorder(self, new_ids: list[str]) -> None:
        with self._lock:
            self._write_index(new_ids)


# ─────────────────────────────────────────────────────────────────────────────
# UI helpers (palette-aware, re-uses ScannerApp conventions)
# ─────────────────────────────────────────────────────────────────────────────

def _T() -> dict:
    """Lazy import of the live palette dict from the main module."""
    try:
        import Snyk_Scanner_GUI as _gui
        return _gui.T
    except Exception:
        return {
            "bg": "#f5f6f8", "panel_bg": "#ffffff", "surface2": "#eef1f7",
            "accent": "#F5A800", "accent_hi": "#c48700", "button_fg": "#ffffff",
            "accent2": "#c8102e", "text": "#0d1b2a", "muted": "#5a6475",
            "border": "#dde2ec", "ok": "#1a7a4a", "err": "#c8102e",
            "card_hover": "#eef1f7",
        }

def _FUI() -> str:
    try:
        import Snyk_Scanner_GUI as _gui
        return _gui._FUI
    except Exception:
        return "Segoe UI"

def _FMONO() -> str:
    try:
        import Snyk_Scanner_GUI as _gui
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
    """
    def __init__(self, master, store: AppInventoryStore,
                 app: Optional[dict] = None):
        super().__init__(master)
        self._store  = store
        self._app    = dict(_EMPTY_APP)
        if app:
            self._app.update(app)
        self.result: Optional[dict] = None
        T = _T(); FUI = _FUI()

        self.transient(master)
        _center_over_main(master, self, 0.68, 0.90)
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
        title_text = ("✏  Edit Application Profile"
                      if app else "➕  New Application Profile")
        tk.Label(hdr, text=title_text, font=(FUI, 14, "bold"),
                 bg=hdr_bg, fg=T["accent"]).pack(side="left")
        tk.Label(hdr, text="Fill in the fields below — only Name is required.",
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
        v_ci         = sv("ci_pipeline")
        v_type       = sv("app_type",       _APP_TYPES[0])
        v_stack      = sv("tech_stack",     _TECH_STACKS[0])
        v_env        = sv("environment",    _ENVIRONMENTS[0])
        v_crit       = sv("criticality",    _CRITICALITY_LEVELS[1])
        v_data       = sv("data_class",     _DATA_CLASSIFICATION[0])
        v_target     = sv("target_path")
        v_dast_url   = sv("dast_url")
        v_api_spec   = sv("api_spec")
        v_notes      = sv("notes")

        # compliance checkboxes
        self._compliance_vars: dict[str, tk.BooleanVar] = {
            t: tk.BooleanVar(value=(t in self._app.get("compliance", [])))
            for t in _COMPLIANCE_TAGS
        }
        # scan stages
        self._stage_vars: dict[str, tk.BooleanVar] = {
            k: tk.BooleanVar(value=(k in self._app.get("scan_stages", ["sca","code"])))
            for k in ("sca","code","dast","api","secrets")
        }

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

        def browse_dir(var):
            def _go():
                d = filedialog.askdirectory(
                    title="Choose target folder",
                    initialdir=var.get() or str(Path.home()))
                if d: var.set(d)
            return _go

        def browse_file(var):
            def _go():
                p = filedialog.askopenfilename(
                    title="Choose API spec file",
                    filetypes=[("Spec","*.json *.yaml *.yml"),("All","*.*")])
                if p: var.set(p)
            return _go

        # ── Section: Identity ─────────────────────────────────────────────────
        s1 = section("🏷  IDENTITY")
        row(s1, "Application Name *", lambda p: entry(p, v_name))
        row(s1, "Description",       lambda p: entry(p, v_desc))
        row(s1, "Owner / Team",      lambda p: entry(p, v_owner))
        row(s1, "Owner e-mail",      lambda p: entry(p, v_email))
        row(s1, "Repository URL",    lambda p: entry(p, v_repo))
        row(s1, "CI / CD Pipeline",  lambda p: entry(p, v_ci))

        # ── Section: Classification ───────────────────────────────────────────
        s2 = section("🔖  CLASSIFICATION")
        row(s2, "Application Type",      lambda p: combo(p, v_type,  _APP_TYPES))
        row(s2, "Technology Stack",      lambda p: combo(p, v_stack, _TECH_STACKS))
        row(s2, "Environment",           lambda p: combo(p, v_env,   _ENVIRONMENTS))
        row(s2, "Business Criticality",  lambda p: combo(p, v_crit,  _CRITICALITY_LEVELS))
        row(s2, "Data Classification",   lambda p: combo(p, v_data,  _DATA_CLASSIFICATION))

        # ── Compliance tags ───────────────────────────────────────────────────
        comp_hdr = tk.Frame(s2, bg=T["panel_bg"]); comp_hdr.pack(fill="x", pady=(8, 4))
        tk.Label(comp_hdr, text="Compliance Frameworks", font=(FUI, 10),
                 bg=T["panel_bg"], fg=T["muted"], anchor="w", width=22).pack(side="left")
        comp_grid = tk.Frame(s2, bg=T["panel_bg"]); comp_grid.pack(fill="x")
        for i, tag in enumerate(_COMPLIANCE_TAGS):
            col = i % 4; row_n = i // 4
            cb = ttk.Checkbutton(comp_grid, text=tag,
                                 variable=self._compliance_vars[tag])
            cb.grid(row=row_n, column=col, sticky="w", padx=(0, 16), pady=1)

        # ── Section: Scan Config ──────────────────────────────────────────────
        s3 = section("🎯  SCAN CONFIGURATION")

        # target folder
        trow = tk.Frame(s3, bg=T["panel_bg"]); trow.pack(fill="x", pady=3)
        tk.Label(trow, text="Target Folder (SCA/SAST)", font=(FUI, 10),
                 bg=T["panel_bg"], fg=T["muted"], anchor="w", width=22).pack(side="left")
        ttk.Entry(trow, textvariable=v_target).pack(side="left", fill="x", expand=True)
        tk.Button(trow, text="Browse…", command=browse_dir(v_target),
                  bg=T["surface2"], fg=T["text"], font=(FUI, 10), relief="flat",
                  padx=8, cursor="hand2").pack(side="left", padx=(6, 0))

        # DAST URL
        drow = tk.Frame(s3, bg=T["panel_bg"]); drow.pack(fill="x", pady=3)
        tk.Label(drow, text="DAST Target URL", font=(FUI, 10),
                 bg=T["panel_bg"], fg=T["muted"], anchor="w", width=22).pack(side="left")
        ttk.Entry(drow, textvariable=v_dast_url).pack(side="left", fill="x", expand=True)

        # API Spec
        arow = tk.Frame(s3, bg=T["panel_bg"]); arow.pack(fill="x", pady=3)
        tk.Label(arow, text="API Spec (URL or file)", font=(FUI, 10),
                 bg=T["panel_bg"], fg=T["muted"], anchor="w", width=22).pack(side="left")
        ttk.Entry(arow, textvariable=v_api_spec).pack(side="left", fill="x", expand=True)
        tk.Button(arow, text="Browse…", command=browse_file(v_api_spec),
                  bg=T["surface2"], fg=T["text"], font=(FUI, 10), relief="flat",
                  padx=8, cursor="hand2").pack(side="left", padx=(6, 0))

        # Scan stages
        stage_row = tk.Frame(s3, bg=T["panel_bg"]); stage_row.pack(fill="x", pady=(8, 0))
        tk.Label(stage_row, text="Default scan stages", font=(FUI, 10),
                 bg=T["panel_bg"], fg=T["muted"], anchor="w", width=22).pack(side="left")
        for key, label in [("sca","SCA"),("code","SAST"),
                            ("dast","DAST"),("api","API"),("secrets","Secrets")]:
            ttk.Checkbutton(stage_row, text=label,
                            variable=self._stage_vars[key]).pack(side="left", padx=(0, 12))

        # ── Section: Notes ────────────────────────────────────────────────────
        s4 = section("📝  NOTES")
        notes_txt = tk.Text(s4, height=4, wrap="word", font=(FUI, 11),
                            bg=T["surface2"], fg=T["text"],
                            insertbackground=T["text"], relief="flat",
                            padx=8, pady=6)
        notes_txt.insert("1.0", self._app.get("notes", ""))
        notes_txt.pack(fill="x")
        self._notes_widget = notes_txt

        # ── Footer ────────────────────────────────────────────────────────────
        tk.Frame(content, bg=T["border"], height=1).pack(fill="x")
        foot = tk.Frame(content, bg=T["panel_bg"], padx=24, pady=12)
        foot.pack(fill="x")
        self._status_lbl = tk.Label(foot, text="", font=(FUI, 10),
                                    bg=T["panel_bg"], fg=T["err"])
        self._status_lbl.pack(side="left")

        def _save():
            name = v_name.get().strip()
            if not name:
                self._status_lbl.config(text="⚠  Application Name is required.")
                return
            a = dict(self._app)
            a["name"]         = name
            a["description"]  = v_desc.get().strip()
            a["owner"]        = v_owner.get().strip()
            a["owner_email"]  = v_email.get().strip()
            a["repo_url"]     = v_repo.get().strip()
            a["ci_pipeline"]  = v_ci.get().strip()
            a["app_type"]     = v_type.get()
            a["tech_stack"]   = v_stack.get()
            a["environment"]  = v_env.get()
            a["criticality"]  = v_crit.get()
            a["data_class"]   = v_data.get()
            a["compliance"]   = [t for t, bv in self._compliance_vars.items() if bv.get()]
            a["target_path"]  = v_target.get().strip()
            a["dast_url"]     = v_dast_url.get().strip()
            a["api_spec"]     = v_api_spec.get().strip()
            a["scan_stages"]  = [k for k, bv in self._stage_vars.items() if bv.get()]
            a["notes"]        = self._notes_widget.get("1.0", "end-1c").strip()
            if not a.get("id"):
                a["id"] = _slugify(name)
            self._store.save_app(a)
            self.result = a
            _close()

        for txt, cmd, bg_key, hi_key in [
            ("Cancel", _close,  "surface2", "card_hover"),
            ("💾  Save Profile", _save, "accent", "accent_hi"),
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
    """
    Builds the full '📦 Apps' tab content into a given parent Frame.
    Designed to be called by ScannerApp._build_tab_apps(parent).

    Parameters
    ----------
    parent      : tk.Frame  — the tab frame allocated by ScannerApp
    master      : tk.Tk     — the main ScannerApp window (for popups)
    store       : AppInventoryStore
    on_load_app : callable(app:dict)  — called when user clicks "Load into scanner"
    """

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
        tk.Label(hdr, text="📦  Application Inventory",
                 font=(FUI, 13, "bold"), bg=T["panel_bg"],
                 fg=T["accent"]).pack(side="left")
        tk.Label(hdr, text="Manage application profiles, switch active context, and track vulnerability trends.",
                 font=(FUI, 10), bg=T["panel_bg"],
                 fg=T["muted"]).pack(side="left", padx=(12, 0))

        # ── Action bar ────────────────────────────────────────────────────────
        abar = tk.Frame(self._parent, bg=T["bg"], padx=18, pady=8)
        abar.pack(fill="x")

        for txt, cmd, bg, hi in [
            ("➕  New App",       self._new_app,    T["accent"],   T["accent_hi"]),
            ("✏  Edit",          self._edit_app,   T["surface2"], T["card_hover"]),
            ("🗑  Delete",        self._delete_app, T["surface2"], T["card_hover"]),
            ("🔄  Refresh",       self.refresh,     T["surface2"], T["card_hover"]),
        ]:
            fg = T["button_fg"] if bg == T["accent"] else T["text"]
            b = tk.Button(abar, text=txt, command=cmd,
                          bg=bg, fg=fg,
                          activebackground=hi, activeforeground=fg,
                          font=(FUI, 11, "bold"), relief="flat",
                          padx=12, pady=5, cursor="hand2")
            b.pack(side="left", padx=(0, 6))

        self._load_btn = tk.Button(
            abar, text="▶  Load into Scanner", command=self._load_into_scanner,
            bg=T["accent2"], fg=T["button_fg"],
            activebackground="#a00d24", activeforeground=T["button_fg"],
            font=(FUI, 11, "bold"), relief="flat",
            padx=12, pady=5, cursor="hand2")
        self._load_btn.pack(side="right")

        self._active_lbl = tk.Label(abar, text="Active app: (none)",
                                    font=(FUI, 10, "bold"),
                                    bg=T["bg"], fg=T["muted"])
        self._active_lbl.pack(side="right", padx=(0, 16))

        # ── Main split: table (left) + detail panel (right) ──────────────────
        split = tk.Frame(self._parent, bg=T["bg"])
        split.pack(fill="both", expand=True, padx=18, pady=(0, 12))

        # Left: inventory treeview
        left = tk.Frame(split, bg=T["panel_bg"],
                        highlightthickness=1, highlightbackground=T["border"])
        left.pack(side="left", fill="both", expand=True)

        tree_hdr = tk.Frame(left, bg=T["accent"], padx=12, pady=5)
        tree_hdr.pack(fill="x")
        tk.Label(tree_hdr, text="APPLICATION REGISTRY",
                 font=(FUI, 10, "bold"), bg=T["accent"],
                 fg=T["button_fg"]).pack(side="left")

        cols = ("name","type","env","crit","vulns","risk","last_scan")
        self._tree = ttk.Treeview(left, columns=cols,
                                  show="headings", height=22)
        headings = [
            ("name",      "Application",      200),
            ("type",      "Type",             120),
            ("env",       "Environment",       90),
            ("crit",      "Criticality",       110),
            ("vulns",     "🐛 C / H / M / L",  140),
            ("risk",      "Risk Tier",          90),
            ("last_scan", "Last Scan",         130),
        ]
        for col, txt, width in headings:
            self._tree.heading(col, text=txt,
                               command=lambda c=col: self._sort_by(c))
            self._tree.column(col, width=width, anchor="w")

        # Tag-based row colouring
        for tier, colour in _RISK_COLORS_LIGHT.items():
            self._tree.tag_configure(
                tier.lower(), foreground=colour,
                font=(_FUI(), 11, "bold") if tier in ("Critical","High") else (_FUI(), 11))

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
        tk.Label(detail_hdr, text="APP DETAILS",
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

    def refresh(self):
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        apps = self._store.list_apps()
        for app in apps:
            vulns = (f"{app.get('vuln_critical',0)} / "
                     f"{app.get('vuln_high',0)} / "
                     f"{app.get('vuln_medium',0)} / "
                     f"{app.get('vuln_low',0)}")
            last  = app.get("last_scan") or "—"
            tier  = app.get("risk_tier", "None")
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
        for w in self._detail_frame.winfo_children():
            w.destroy()

        if app is None:
            tk.Label(self._detail_frame,
                     text="Select an app\nfrom the list.",
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

        tier  = app.get("risk_tier", "None")
        tc    = _RISK_COLORS_LIGHT.get(tier, T["muted"])
        kv("Name",       app.get("name",""),       bold=True)
        kv("Risk Tier",  tier,                     bold=True, color=tc)
        kv("Type",       app.get("app_type",""))
        kv("Stack",      app.get("tech_stack",""))
        kv("Environment",app.get("environment",""))
        kv("Criticality",app.get("criticality",""))
        kv("Data Class", app.get("data_class",""))

        tk.Frame(pad, bg=T["border"], height=1).pack(fill="x", pady=8)

        # Vulnerability badge row
        c = app.get("vuln_critical",0)
        h = app.get("vuln_high",0)
        m = app.get("vuln_medium",0)
        lo = app.get("vuln_low",0)
        tot = app.get("vuln_total", c+h+m+lo)

        badge_row = tk.Frame(pad, bg=T["panel_bg"]); badge_row.pack(fill="x")
        for count, label, bg_hex in [
            (c,  "Critical", "#7a0c1c"),
            (h,  "High",     "#8b3a0a"),
            (m,  "Medium",   "#7a5e00"),
            (lo, "Low",      "#0c4a2b"),
        ]:
            badge = tk.Frame(badge_row, bg=bg_hex,
                             padx=6, pady=4)
            badge.pack(side="left", padx=(0, 4))
            tk.Label(badge, text=str(count), font=(FUI, 12, "bold"),
                     bg=bg_hex, fg="#ffffff").pack()
            tk.Label(badge, text=label, font=(FUI, 8),
                     bg=bg_hex, fg="#cccccc").pack()

        kv("Total Vulns", str(tot))
        kv("Secrets",     str(app.get("secrets_total",0)))
        kv("Last Scan",   (app.get("last_scan") or "—")[:16])
        kv("Last Mode",   app.get("last_mode","—"))

        tk.Frame(pad, bg=T["border"], height=1).pack(fill="x", pady=8)

        kv("Owner",      app.get("owner",""))
        kv("Email",      app.get("owner_email",""))
        kv("Target",     app.get("target_path","")[-40:] if app.get("target_path") else "—")
        kv("DAST URL",   app.get("dast_url",""))

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
            tk.Label(pad, text="NOTES",
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
        tk.Label(parent, text="VULNERABILITY TREND (last scans)",
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
        win.title("Delete App")
        win.configure(bg=T["bg"])
        win.transient(self._master)
        _center_over_main(self._master, win, 0.32, 0.18)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        border = tk.Frame(win, bg=T["accent"], padx=2, pady=2)
        border.pack(fill="both", expand=True)
        inner = tk.Frame(border, bg=T["bg"], padx=24, pady=16)
        inner.pack(fill="both", expand=True)
        tk.Label(inner, text=f"Delete '{app['name']}'?\nThis action cannot be undone.",
                 font=(FUI, 11), bg=T["bg"], fg=T["text"],
                 justify="center").pack(pady=(0, 14))
        btn_row = tk.Frame(inner, bg=T["bg"]); btn_row.pack()
        def _confirm():
            self._store.delete_app(app["id"])
            if self._current_app and self._current_app.get("id") == app["id"]:
                self._current_app = None
                self._active_lbl.config(text="Active app: (none)", fg=_T()["muted"])
            win.destroy()
            self.refresh()
            self._show_detail(None)
        tk.Button(btn_row, text="Cancel", command=win.destroy,
                  bg=T["surface2"], fg=T["text"], font=(FUI, 11),
                  relief="flat", padx=10, pady=5, cursor="hand2").pack(side="left", padx=(0, 8))
        tk.Button(btn_row, text="🗑  Delete",command=_confirm,
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
        self._active_lbl.config(
            text=f"Active: {app['name']}", fg=T["accent"])
        if self._on_load_app:
            self._on_load_app(app)

    # ── Public API called from ScannerApp ─────────────────────────────────────

    def get_active_app(self) -> Optional[dict]:
        return self._current_app

    def push_scan_result(self, app_id: str, meta: dict) -> None:
        """Called by ScannerApp after a scan to update inventory counts."""
        self._store.record_scan(app_id, meta)
        self.refresh()
        # Re-paint detail if this app is visible
        sel = self._tree.selection()
        if sel and sel[0] == app_id:
            self._show_detail(self._store.get_app(app_id))
