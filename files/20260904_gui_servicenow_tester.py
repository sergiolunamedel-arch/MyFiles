#!/usr/bin/env python3

from __future__ import annotations

import platform
import queue
import threading
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, messagebox

import test_servicenow_ticket as core


_SYSTEM = platform.system()
if _SYSTEM == "Darwin":
    _FUI, _FUI_TITLE, _FMONO = "SF Pro Text", "SF Pro Display", "Menlo"
elif _SYSTEM == "Linux":
    _FUI, _FUI_TITLE, _FMONO = "DejaVu Sans", "DejaVu Sans", "DejaVu Sans Mono"
else:
    _FUI, _FUI_TITLE, _FMONO = "Calibri", "Segoe UI Semibold", "Cascadia Mono"

_PALETTE_LIGHT = {
    "bg": "#ffffff", "panel_bg": "#fefefe", "surface2": "#fdfdfd",
    "accent": "#F5A800", "accent_hi": "#c48700", "button_fg": "#ffffff",
    "accent2": "#c8102e", "accent2_hi": "#a00d24",
    "text": "#0d1b2a", "muted": "#5a6475", "border": "#dde2ec",
    "card_fg": "#000000",
    "ok": "#1a7a4a", "err": "#c8102e", "card_hover": "#eef1f7",
    "tree_bg": "#fefefe",
}
_PALETTE_DARK = {
    "bg": "#000000", "panel_bg": "#010101", "surface2": "#020202",
    "accent": "#F5A800", "accent_hi": "#c48700", "button_fg": "#000000",
    "accent2": "#c8102e", "accent2_hi": "#a00d24",
    "text": "#f0f1f3", "muted": "#6b7280", "border": "#252830",
    "card_fg": "#ffffff",
    "ok": "#22c55e", "err": "#ef4444", "card_hover": "#1e2127",
    "tree_bg": "#010101",
}
T = dict(_PALETTE_LIGHT)

_CARD_GAP = 6
_ENV_LABELS = {"dev": "Development", "qa": "QA", "prod": "Producción"}
_ENV_ICON = {"dev": "🧪", "qa": "🧭", "prod": "⚠"}
_ENV_AMBIENTE_DEFAULT = {"dev": "Desarrollo", "qa": "QA", "prod": "Producción"}


def _tag(widget: tk.Widget, **roles: str) -> tk.Widget:
    """Marca un widget con los roles de color (opción -> clave de T) que _repaint_widget debe
    reaplicar cada vez que cambia el tema. Evita tener que adivinar el rol a partir del color
    actual (lo que en el programa original causaba colisiones cuando dos roles comparten hex)."""
    widget._theme_roles = roles
    return widget


class ServiceNowTesterApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ServiceNow Ticket Tester — SecDevOps Banco Base")
        self.geometry("1180x820")
        self.minsize(1020, 700)

        self.dark = False
        self.msg_queue: queue.Queue = queue.Queue()
        self._env: dict[str, dict] = {}
        self._env_frames: dict[str, tk.Frame] = {}
        self._active_env = "dev"

        self._build_ui()
        self._maximize_window()
        self.after(100, self._poll_queue)

    # ---------------------------------------------------------------- tema / paleta ----

    def _apply_palette(self):
        T.update(_PALETTE_DARK if self.dark else _PALETTE_LIGHT)

    def _repaint_widget(self, w: tk.Widget):
        roles = getattr(w, "_theme_roles", None)
        if roles:
            cfg = {opt: T[role] for opt, role in roles.items()}
            try:
                w.configure(**cfg)
            except tk.TclError:
                pass
        for child in w.winfo_children():
            self._repaint_widget(child)

    def _toggle_theme(self):
        self.dark = not self.dark
        self._apply_palette()
        self.configure(bg=T["bg"])
        self._repaint_widget(self)
        self._setup_ttk_style()
        self._theme_btn.configure(text="☀" if self.dark else "🌙")
        self._recolor_env_tabs()

    def _setup_ttk_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TNotebook", background=T["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=T["surface2"], foreground=T["text"],
                        font=(_FUI, 11), padding=(14, 8))
        style.map("TNotebook.Tab",
                  background=[("selected", T["accent"])],
                  foreground=[("selected", "#ffffff")])

        style.configure("TFrame", background=T["panel_bg"])
        style.configure("TLabelframe", background=T["panel_bg"], foreground=T["text"])
        style.configure("TLabelframe.Label", background=T["panel_bg"], foreground=T["text"],
                        font=(_FUI, 11, "bold"))
        style.configure("TLabel", background=T["panel_bg"], foreground=T["text"], font=(_FUI, 11))
        style.configure("TCheckbutton", background=T["panel_bg"], foreground=T["text"], font=(_FUI, 11))
        style.map("TCheckbutton", background=[("active", T["panel_bg"])])
        style.configure("TEntry", fieldbackground=T["surface2"], foreground=T["text"],
                        insertcolor=T["text"], bordercolor=T["border"])

        style.configure("Treeview", background=T["tree_bg"], fieldbackground=T["tree_bg"],
                        foreground=T["text"], font=(_FUI, 10), rowheight=22,
                        bordercolor=T["border"], borderwidth=1)
        style.configure("Treeview.Heading", background=T["surface2"], foreground=T["text"],
                        font=(_FUI, 10, "bold"))
        style.map("Treeview", background=[("selected", T["accent"])],
                  foreground=[("selected", "#ffffff")])

    # ---------------------------------------------------------------- construcción UI ----

    def _build_ui(self):
        self._apply_palette()
        self.configure(bg=T["bg"])
        self._setup_ttk_style()
        self._build_ribbon()
        self._build_body()
        self._show_env(self._active_env)

    def _build_ribbon(self):
        ribbon = tk.Frame(self, bg=T["bg"])
        ribbon.pack(side="top", fill="x")
        _tag(ribbon, bg="bg")

        top_row = tk.Frame(ribbon, bg=T["bg"])
        top_row.pack(fill="x", side="top")
        _tag(top_row, bg="bg")
        top_border = tk.Frame(ribbon, bg=T["border"], height=2)
        top_border.pack(fill="x", side="top", before=top_row)
        _tag(top_border, bg="border")

        brand = tk.Frame(top_row, bg=T["bg"])
        brand.pack(side="left", padx=(10, 0), pady=8)
        _tag(brand, bg="bg")
        b1 = tk.Label(brand, text="🎫 ServiceNow Ticket Tester", font=(_FUI_TITLE, 13, "bold"),
                     bg=T["bg"], fg=T["accent"])
        b1.pack(side="left")
        _tag(b1, bg="bg", fg="accent")
        b2 = tk.Label(brand, text="  ·  SecDevOps Banco Base", font=(_FUI_TITLE, 11),
                     bg=T["bg"], fg=T["muted"])
        b2.pack(side="left")
        _tag(b2, bg="bg", fg="muted")

        right = tk.Frame(top_row, bg=T["bg"])
        right.pack(side="right", padx=10, pady=6)
        _tag(right, bg="bg")
        self._theme_btn = tk.Button(right, text="🌙", font=(_FUI, 14), command=self._toggle_theme,
                                    bg=T["bg"], fg=T["muted"], activebackground=T["bg"],
                                    activeforeground=T["accent"], relief="flat", bd=0, cursor="hand2")
        self._theme_btn.pack(side="right")
        _tag(self._theme_btn, bg="bg", fg="muted")

        mid_border = tk.Frame(ribbon, bg=T["border"], height=1)
        mid_border.pack(fill="x")
        _tag(mid_border, bg="border")

        tab_row = tk.Frame(ribbon, bg=T["bg"])
        tab_row.pack(fill="x", side="top")
        _tag(tab_row, bg="bg")

        _tab_font = (_FUI_TITLE, 12, "bold")
        _measure = tkfont.Font(family=_FUI_TITLE, size=12, weight="bold")
        _tab_w = max(_measure.measure(f"{_ENV_ICON[k]}  {v}") for k, v in _ENV_LABELS.items()) + 40

        self._env_tab_btns: dict[str, tk.Button] = {}
        self._env_tab_underlines: dict[str, tk.Frame] = {}
        for key in core.ENVIRONMENT_KEYS:
            wrap = tk.Frame(tab_row, width=_tab_w, height=38, bg=T["bg"])
            wrap.pack_propagate(False)
            wrap.pack(side="left")
            _tag(wrap, bg="bg")

            btn = tk.Button(wrap, text=f"{_ENV_ICON[key]}  {_ENV_LABELS[key]}",
                            command=lambda k=key: self._show_env(k),
                            font=_tab_font, relief="flat", bd=0, cursor="hand2",
                            bg=T["bg"], fg=T["muted"],
                            activebackground=T["bg"], activeforeground=T["accent"])
            btn.pack(fill="both", expand=True)
            self._env_tab_btns[key] = btn

            underline = tk.Frame(wrap, height=3, bg=T["bg"])
            underline.pack(side="bottom", fill="x")
            self._env_tab_underlines[key] = underline

        bottom_border = tk.Frame(ribbon, bg=T["border"], height=2)
        bottom_border.pack(fill="x", side="bottom")
        _tag(bottom_border, bg="border")

    def _recolor_env_tabs(self):
        for key, btn in self._env_tab_btns.items():
            active = key == self._active_env
            danger = key == "prod"
            fg = (T["accent2"] if danger else T["accent"]) if active else \
                 (T["accent2"] if danger else T["muted"])
            btn.configure(bg=T["bg"], fg=fg, activebackground=T["bg"],
                         activeforeground=T["accent2"] if danger else T["accent"])
            self._env_tab_underlines[key].configure(
                bg=(T["accent2"] if danger else T["accent"]) if active else T["bg"])

    def _show_env(self, key: str):
        self._active_env = key
        self._recolor_env_tabs()
        for k, frame in self._env_frames.items():
            if k == key:
                frame.tkraise()
        if key in getattr(self, "_env_canvas_wheel", {}):
            self._bind_active_wheel(key)

    def _build_body(self):
        container = tk.Frame(self, bg=T["bg"])
        container.pack(fill="both", expand=True)
        _tag(container, bg="bg")

        for key in core.ENVIRONMENT_KEYS:
            frame = tk.Frame(container, bg=T["bg"])
            frame.place(x=0, y=0, relwidth=1, relheight=1)
            _tag(frame, bg="bg")
            self._env_frames[key] = frame
            self._build_env_panel(frame, key)

    # ---------------------------------------------------------------- helpers de estilo ----

    def _lbl(self, parent, text="", size=11, bold=False, fg_role="card_fg", **kw) -> tk.Label:
        """fg_role is a key into T (e.g. 'card_fg', 'muted', 'accent2'), not a literal colour —
        so the label recolours correctly on theme toggle instead of freezing at whatever hex it
        was built with."""
        w = tk.Label(parent, text=text, font=(_FUI, size, "bold" if bold else "normal"),
                     bg=T["panel_bg"], fg=T[fg_role], **kw)
        w._theme_roles = {"bg": "panel_bg", "fg": fg_role}
        return w

    def _btn(self, parent, text, cmd, *, danger=False, **kw) -> tk.Button:
        role = "accent2" if danger else "accent"
        cfg = dict(bg=T[role], fg="#ffffff", activebackground=T[role + "_hi"],
                  activeforeground="#ffffff", disabledforeground=T["muted"],
                  font=(_FUI, 11), padx=12, pady=8, cursor="hand2", bd=0, relief="flat")
        cfg.update(kw)
        w = tk.Button(parent, text=text, command=cmd, **cfg)
        _tag(w, bg=role, fg=None)
        w._theme_roles = {"bg": role}
        return w

    def _icon_btn(self, parent, text, cmd, *, fg_role="text", **kw) -> tk.Button:
        cfg = dict(bg=T["surface2"], fg=T[fg_role], activebackground=T["card_hover"],
                  activeforeground=T["accent"], font=(_FUI, 11), padx=8, pady=4,
                  cursor="hand2", bd=0, relief="flat")
        cfg.update(kw)
        w = tk.Button(parent, text=text, command=cmd, **cfg)
        w._theme_roles = {"bg": "surface2", "fg": fg_role}
        return w

    def _card(self, parent, title="", *, danger_border=False) -> tk.Frame:
        outer = tk.Frame(parent, bg=T["panel_bg"], highlightthickness=1,
                         highlightbackground=T["accent2"] if danger_border else T["border"])
        outer.pack(fill="x", pady=(0, _CARD_GAP), padx=2)
        _tag(outer, bg="panel_bg", highlightbackground="accent2" if danger_border else "border")
        if title:
            hdr = tk.Frame(outer, bg=T["panel_bg"])
            hdr.pack(fill="x", padx=10, pady=(8, 0))
            _tag(hdr, bg="panel_bg")
            t = tk.Label(hdr, text=title, font=(_FUI_TITLE, 11, "bold"), bg=T["panel_bg"], fg=T["text"])
            t.pack(side="left")
            _tag(t, bg="panel_bg", fg="text")
        inner = tk.Frame(outer, bg=T["panel_bg"])
        inner.pack(fill="both", expand=True, padx=10, pady=8)
        _tag(inner, bg="panel_bg")
        return inner

    def _safety_banner(self, parent, text: str, *, danger=False) -> tk.Frame:
        role = "accent2" if danger else "accent"
        f = tk.Frame(parent, bg=T["panel_bg"], highlightthickness=2, highlightbackground=T[role])
        f.pack(fill="x", pady=(0, _CARD_GAP), padx=2)
        _tag(f, bg="panel_bg", highlightbackground=role)
        inner = tk.Frame(f, bg=T["panel_bg"])
        inner.pack(fill="x", padx=10, pady=8)
        _tag(inner, bg="panel_bg")
        icon = tk.Label(inner, text="⚠", font=(_FUI, 14, "bold"), bg=T["panel_bg"], fg=T[role])
        icon.pack(side="left")
        _tag(icon, bg="panel_bg", fg=role)
        lbl = tk.Label(inner, text=text, font=(_FUI, 10, "bold"), bg=T["panel_bg"], fg=T["text"],
                       anchor="w", justify="left", wraplength=900)
        lbl.pack(side="left", padx=(8, 0), fill="x", expand=True)
        _tag(lbl, bg="panel_bg", fg="text")
        return f

    # ---------------------------------------------------------------- scroll ----

    def _scrollable(self, parent: tk.Frame, env_key: str) -> tk.Frame:
        """Wraps a tab's content in a mouse-wheel-scrollable Canvas — the credenciales/conexión/
        ejecutar/log stack is taller than fits in one screen (confirmed by measuring real widget
        geometry under Xvfb: without this, the Log card was being squeezed to 0px height by pack
        once the window ran out of vertical room), so every environment panel needs to scroll."""
        outer = tk.Frame(parent, bg=T["bg"])
        outer.pack(fill="both", expand=True)
        _tag(outer, bg="bg")

        canvas = tk.Canvas(outer, bg=T["bg"], highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        _tag(canvas, bg="bg")

        inner = tk.Frame(canvas, bg=T["bg"])
        _tag(inner, bg="bg")
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        padded = tk.Frame(inner, bg=T["bg"])
        padded.pack(fill="both", expand=True, padx=10, pady=8)
        _tag(padded, bg="bg")

        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win_id, width=e.width))

        def _on_wheel(e):
            delta = int(-1 * (e.delta / 120)) if e.delta else (1 if e.num == 5 else -1)
            canvas.yview_scroll(delta, "units")

        self._env_canvas_wheel = getattr(self, "_env_canvas_wheel", {})
        self._env_canvas_wheel[env_key] = (canvas, _on_wheel)
        return padded

    def _bind_active_wheel(self, key: str):
        for k, (canvas, handler) in getattr(self, "_env_canvas_wheel", {}).items():
            canvas.unbind_all("<MouseWheel>") if k == key else None
        canvas, handler = self._env_canvas_wheel[key]
        canvas.bind_all("<MouseWheel>", handler)
        canvas.bind_all("<Button-4>", handler)
        canvas.bind_all("<Button-5>", handler)

    # ---------------------------------------------------------------- panel por ambiente ----

    def _build_env_panel(self, parent: tk.Frame, key: str):
        env = core.load_environment(key)
        ui: dict = {"env": env, "running": False, "ticket_rows": {}}
        self._env[key] = ui

        scroll_outer = self._scrollable(parent, key)

        if key == "prod":
            self._safety_banner(
                scroll_outer,
                "PRODUCCIÓN — esta pestaña habla con la instancia real de ServiceNow. "
                "Los tickets que crees o canceles aquí son reales, no de prueba.",
                danger=True,
            )

        # --- Conexión -------------------------------------------------------------------
        conn = self._card(scroll_outer, "Conexión")
        row1 = tk.Frame(conn, bg=T["panel_bg"]); row1.pack(fill="x", pady=2); _tag(row1, bg="panel_bg")
        self._lbl(row1, "URL de instancia:").pack(side="left", padx=(0, 4))
        url_entry = ttk.Entry(row1, width=42)
        url_entry.insert(0, env.base_url)
        url_entry.pack(side="left", padx=(0, 16))
        ui["url_entry"] = url_entry

        self._lbl(row1, "Catalog item sys_id:").pack(side="left", padx=(0, 4))
        sysid_entry = ttk.Entry(row1, width=36)
        sysid_entry.insert(0, env.sys_id)
        sysid_entry.pack(side="left", padx=(0, 16))
        ui["sysid_entry"] = sysid_entry

        self._icon_btn(row1, "💾 Guardar conexión", lambda k=key: self._on_save_connection(k)).pack(side="left")

        if key != "dev" and not (env.base_url and env.sys_id):
            hint = self._lbl(conn, f"Aún no configurada — pídele a alguien con acceso la URL de la "
                                    f"instancia {_ENV_LABELS[key]} de ServiceNow y el sys_id de este "
                                    f"catalog item, y guárdalos arriba.",
                              size=9, fg_role="muted")
            hint.pack(fill="x", pady=(4, 0))

        # --- Credenciales -----------------------------------------------------------------
        remember_note = "texto plano — cuidado en equipos compartidos" if key != "prod" else \
                        "texto plano — usa una cuenta de servicio, NO tu cuenta con privilegios"
        creds = self._card(scroll_outer, "Credenciales")
        crow = tk.Frame(creds, bg=T["panel_bg"]); crow.pack(fill="x", pady=2); _tag(crow, bg="panel_bg")
        self._lbl(crow, "Usuario:").pack(side="left", padx=(0, 4))
        user_entry = ttk.Entry(crow, width=18); user_entry.pack(side="left", padx=(0, 10))
        self._lbl(crow, "Password:").pack(side="left", padx=(0, 4))
        pass_entry = ttk.Entry(crow, width=18, show="•"); pass_entry.pack(side="left", padx=(0, 10))
        self._lbl(crow, "Token (opcional):").pack(side="left", padx=(0, 4))
        token_entry = ttk.Entry(crow, width=16, show="•"); token_entry.pack(side="left")
        ui.update(user_entry=user_entry, pass_entry=pass_entry, token_entry=token_entry)

        crow2 = tk.Frame(creds, bg=T["panel_bg"]); crow2.pack(fill="x", pady=(6, 0)); _tag(crow2, bg="panel_bg")
        remember_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(crow2, text=f"Recordar en este equipo ({remember_note})",
                        variable=remember_var).pack(side="left")
        ui["remember_var"] = remember_var
        self._icon_btn(crow2, "Olvidar credenciales guardadas",
                       lambda k=key: self._on_forget(k)).pack(side="left", padx=(16, 0))

        self._load_saved_credentials(key)

        # --- Notebook interno: Ejecutar pruebas / Tickets existentes ----------------------
        notebook = ttk.Notebook(scroll_outer)
        notebook.pack(fill="both", expand=True, pady=(0, _CARD_GAP))
        run_tab = tk.Frame(notebook, bg=T["panel_bg"]); _tag(run_tab, bg="panel_bg")
        tickets_tab = tk.Frame(notebook, bg=T["panel_bg"]); _tag(tickets_tab, bg="panel_bg")
        notebook.add(run_tab, text="Ejecutar pruebas")
        notebook.add(tickets_tab, text="Tickets existentes")

        self._build_run_tab(run_tab, key)
        self._build_tickets_tab(tickets_tab, key)

        # --- Log ---------------------------------------------------------------------------
        log_card = self._card(scroll_outer, "Log")
        log_text = tk.Text(log_card, wrap="word", state="disabled", height=8,
                           bg=T["surface2"], fg=T["text"], insertbackground=T["text"],
                           relief="flat", font=(_FMONO, 9))
        _tag(log_text, bg="surface2", fg="text", insertbackground="text")
        scrollbar = ttk.Scrollbar(log_card, command=log_text.yview)
        log_text.configure(yscrollcommand=scrollbar.set)
        log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        ui["log_text"] = log_text

        self._log(key, f"Log CSV: {self._log_file_for(key)}")
        if not (env.base_url and env.sys_id) and key != "dev":
            self._log(key, "(configura la URL de instancia y el sys_id del catalog item arriba antes de ejecutar pruebas)")

    def _build_run_tab(self, parent: tk.Frame, key: str):
        ui = self._env[key]
        is_prod = ui["env"].is_production

        scen_frame = self._card(parent, "Servicios a incluir en el ticket (se crea UNO solo con todo lo marcado)")
        scenario_vars: dict[str, tk.BooleanVar] = {}
        for i, name in enumerate(core.SERVICES.keys()):
            var = tk.BooleanVar(value=True)
            scenario_vars[name] = var
            ttk.Checkbutton(scen_frame, text=name, variable=var).grid(row=0, column=i, sticky="w", padx=10, pady=4)
        ui["scenario_vars"] = scenario_vars

        opts = self._card(parent, "Opciones")

        row0 = tk.Frame(opts, bg=T["panel_bg"]); row0.pack(fill="x", pady=2); _tag(row0, bg="panel_bg")
        self._lbl(row0, "Ambiente (opcional):").pack(side="left", padx=(0, 4))
        ambiente_entry = ttk.Entry(row0, width=20)
        ambiente_entry.insert(0, _ENV_AMBIENTE_DEFAULT[key])
        ambiente_entry.pack(side="left", padx=(0, 16))
        ui["ambiente_entry"] = ambiente_entry

        dry_run_var = tk.BooleanVar(value=is_prod)  # en Producción arranca en dry-run por seguridad
        ttk.Checkbutton(row0, text="Dry run (no envía nada)", variable=dry_run_var).pack(side="left", padx=(0, 16))
        ui["dry_run_var"] = dry_run_var

        cleanup_var = tk.BooleanVar(value=not is_prod)  # en Producción no se auto-cancela por default
        ttk.Checkbutton(row0, text="Cancelar tickets de prueba al terminar", variable=cleanup_var).pack(side="left")
        ui["cleanup_var"] = cleanup_var

        row1 = tk.Frame(opts, bg=T["panel_bg"]); row1.pack(fill="x", pady=2); _tag(row1, bg="panel_bg")
        self._lbl(row1, "Nombre de la aplicación:").pack(side="left", padx=(0, 4))
        app_name_entry = ttk.Entry(row1, width=28)
        app_name_entry.insert(0, core.DEFAULT_APP_NAME)
        app_name_entry.pack(side="left", padx=(0, 16))
        ui["app_name_entry"] = app_name_entry

        self._lbl(row1, "Descripción / justificación:").pack(side="left", padx=(0, 4))
        descripcion_entry = ttk.Entry(row1, width=40)
        descripcion_entry.insert(0, core.DEFAULT_DESCRIPTION)
        descripcion_entry.pack(side="left")
        ui["descripcion_entry"] = descripcion_entry

        row2 = tk.Frame(opts, bg=T["panel_bg"]); row2.pack(fill="x", pady=2); _tag(row2, bg="panel_bg")
        self._lbl(row2, "Nombre del solicitante:").pack(side="left", padx=(0, 4))
        sol_nombre = ttk.Entry(row2, width=28)
        sol_nombre.insert(0, core.BASE_FIELDS.get("nombre_del_solicitante", ""))
        sol_nombre.pack(side="left", padx=(0, 16))
        ui["solicitante_nombre_entry"] = sol_nombre

        self._lbl(row2, "Correo del solicitante:").pack(side="left", padx=(0, 4))
        sol_correo = ttk.Entry(row2, width=28)
        sol_correo.insert(0, core.BASE_FIELDS.get("correo_del_solicitante", ""))
        sol_correo.pack(side="left")
        ui["solicitante_correo_entry"] = sol_correo

        row3 = tk.Frame(opts, bg=T["panel_bg"]); row3.pack(fill="x", pady=2); _tag(row3, bg="panel_bg")
        self._lbl(row3, "ID (usuario) del solicitante:").pack(side="left", padx=(0, 4))
        sol_id = ttk.Entry(row3, width=18)
        sol_id.insert(0, core.BASE_FIELDS.get("id_del_solicitante", ""))
        sol_id.pack(side="left")
        ui["solicitante_id_entry"] = sol_id

        row4 = tk.Frame(opts, bg=T["panel_bg"]); row4.pack(fill="x", pady=(6, 2)); _tag(row4, bg="panel_bg")
        self._lbl(row4, "Overrides (una var=valor por línea):").pack(anchor="w")
        overrides_text = tk.Text(opts, width=70, height=3, bg=T["surface2"], fg=T["text"],
                                 insertbackground=T["text"], relief="flat", font=(_FMONO, 9))
        _tag(overrides_text, bg="surface2", fg="text", insertbackground="text")
        overrides_text.pack(fill="x", pady=(2, 0))
        ui["overrides_text"] = overrides_text

        run_frame = tk.Frame(parent, bg=T["panel_bg"]); run_frame.pack(fill="x", pady=(0, 4)); _tag(run_frame, bg="panel_bg")
        run_button = self._btn(run_frame, "▶ Ejecutar pruebas", lambda k=key: self._on_run(k), danger=is_prod)
        run_button.pack(side="left")
        ui["run_button"] = run_button

        inspect_button = self._icon_btn(run_frame, "Inspeccionar variables obligatorias",
                                        lambda k=key: self._on_inspect(k))
        inspect_button.pack(side="left", padx=8)
        ui["inspect_button"] = inspect_button

        self._lbl(run_frame, "Campo:").pack(side="left", padx=(12, 2))
        inspect_field_entry = ttk.Entry(run_frame, width=20)
        inspect_field_entry.pack(side="left")
        ui["inspect_field_entry"] = inspect_field_entry
        inspect_field_button = self._icon_btn(run_frame, "Detalle de campo",
                                              lambda k=key: self._on_inspect_field(k))
        inspect_field_button.pack(side="left", padx=4)
        ui["inspect_field_button"] = inspect_field_button

        status_label = self._lbl(run_frame, "Listo", fg_role="muted")
        status_label.pack(side="left", padx=12)
        ui["status_label"] = status_label

        table_card = self._card(parent, "Resultados")
        columns = ("scenario", "status", "request_number", "cleanup_status")
        tree = ttk.Treeview(table_card, columns=columns, show="headings", height=6)
        headings = {"scenario": "Servicios incluidos", "status": "Status",
                    "request_number": "Request #", "cleanup_status": "Limpieza"}
        for col in columns:
            tree.heading(col, text=headings[col])
            tree.column(col, width=220 if col == "scenario" else (180 if col == "request_number" else 140), anchor="w")
        tree.pack(fill="x")
        tree.bind("<Control-c>", lambda e, k=key: self._on_copy_request_number(k, e))
        tree.bind("<Control-C>", lambda e, k=key: self._on_copy_request_number(k, e))
        ui["tree"] = tree

        self._lbl(parent, "Selecciona una fila (o varias con Ctrl+clic) y presiona Ctrl+C para copiar el Request #.",
                  size=9, fg_role="muted").pack(fill="x", padx=4)

    def _build_tickets_tab(self, parent: tk.Frame, key: str):
        ui = self._env[key]

        toolbar = tk.Frame(parent, bg=T["panel_bg"]); toolbar.pack(fill="x", padx=8, pady=6); _tag(toolbar, bg="panel_bg")
        self._lbl(toolbar, "Mostrar últimos:").pack(side="left")
        limit_entry = ttk.Entry(toolbar, width=5); limit_entry.insert(0, "25"); limit_entry.pack(side="left", padx=4)
        ui["ticket_limit_entry"] = limit_entry

        refresh_btn = self._icon_btn(toolbar, "Actualizar lista", lambda k=key: self._on_refresh_tickets(k))
        refresh_btn.pack(side="left", padx=8)
        ui["refresh_button"] = refresh_btn
        select_all_btn = self._icon_btn(toolbar, "Seleccionar todos", lambda k=key: self._on_select_all_tickets(k))
        select_all_btn.pack(side="left", padx=4)
        ui["select_all_button"] = select_all_btn
        cancel_btn = self._icon_btn(toolbar, "Cancelar seleccionados",
                                    lambda k=key: self._on_cancel_selected_tickets(k), fg_role="err")
        cancel_btn.pack(side="left", padx=4)
        ui["cancel_selected_button"] = cancel_btn
        audit_btn = self._icon_btn(toolbar, "Auditar seleccionado", lambda k=key: self._on_audit_selected_ticket(k))
        audit_btn.pack(side="left", padx=4)
        ui["audit_selected_button"] = audit_btn

        self._lbl(parent,
                  "Ctrl+clic / Shift+clic para seleccionar varios. 'Auditar seleccionado' muestra en el Log "
                  "quién/qué cambió el estado del ticket.", size=9, fg_role="muted").pack(fill="x", padx=8)

        table_frame = tk.Frame(parent, bg=T["panel_bg"]); table_frame.pack(fill="both", expand=True, padx=8, pady=6)
        _tag(table_frame, bg="panel_bg")
        columns = ("ritm_number", "state", "created", "short_description")
        tickets_tree = ttk.Treeview(table_frame, columns=columns, show="headings",
                                    selectmode="extended", height=16)
        headings = {"ritm_number": "RITM", "state": "Estado", "created": "Creado",
                    "short_description": "Aplicación / Descripción"}
        widths = {"ritm_number": 120, "state": 160, "created": 150, "short_description": 380}
        for col in columns:
            tickets_tree.heading(col, text=headings[col])
            tickets_tree.column(col, width=widths[col], anchor="w")
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=tickets_tree.yview)
        tickets_tree.configure(yscrollcommand=vsb.set)
        tickets_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        ui["tickets_tree"] = tickets_tree

    # ---------------------------------------------------------------- conexión ----

    def _on_save_connection(self, key: str):
        ui = self._env[key]
        env = ui["env"]
        env.base_url = ui["url_entry"].get().strip().rstrip("/")
        env.sys_id = ui["sysid_entry"].get().strip()
        core.save_environment(env)
        self._log(key, f"Conexión guardada: {env.base_url or '(vacío)'}  |  sys_id={env.sys_id or '(vacío)'}")

    def _log_file_for(self, key: str) -> str:
        if key == "dev":
            return core.LOG_FILE
        import os
        return os.path.join(os.path.dirname(core.LOG_FILE), f"servicenow_test_log_{key}.csv")

    # ---------------------------------------------------------------- credenciales ----

    def _load_saved_credentials(self, key: str):
        ui = self._env[key]
        creds = core.load_saved_credentials(credentials_file=ui["env"].credentials_file)
        if not creds:
            return
        if creds.get("user"):
            ui["user_entry"].insert(0, creds["user"])
        if creds.get("password"):
            ui["pass_entry"].insert(0, creds["password"])
        if creds.get("token"):
            ui["token_entry"].insert(0, creds["token"])
        ui["remember_var"].set(True)

    def _maybe_save_credentials(self, key: str):
        ui = self._env[key]
        if ui["remember_var"].get():
            core.save_credentials(
                user=ui["user_entry"].get().strip(),
                password=ui["pass_entry"].get(),
                token=ui["token_entry"].get().strip(),
                credentials_file=ui["env"].credentials_file,
            )

    def _on_forget(self, key: str):
        ui = self._env[key]
        core.clear_saved_credentials(credentials_file=ui["env"].credentials_file)
        ui["remember_var"].set(False)
        self._log(key, "Credenciales guardadas eliminadas.")

    def _get_auth(self, key: str):
        ui = self._env[key]
        token = ui["token_entry"].get().strip()
        user = ui["user_entry"].get().strip()
        password = ui["pass_entry"].get()
        if token:
            return None, {"Authorization": f"Bearer {token}"}
        return (user, password), {}

    def _has_credentials(self, key: str) -> bool:
        ui = self._env[key]
        return bool(ui["token_entry"].get().strip()) or \
               bool(ui["user_entry"].get().strip() and ui["pass_entry"].get())

    def _has_connection(self, key: str) -> bool:
        env = self._env[key]["env"]
        return bool(env.base_url and env.sys_id)

    # ---------------------------------------------------------------- log / status / queue ----

    def _log(self, key: str, message: str):
        self.msg_queue.put((key, "log", message))

    def _set_status(self, key: str, text: str):
        self._env[key]["status_label"].configure(text=text)
        self._log(key, f"[status] {text}")

    def _set_buttons_state(self, key: str, state: str):
        ui = self._env[key]
        for name in ("run_button", "inspect_button", "inspect_field_button",
                    "refresh_button", "select_all_button", "cancel_selected_button",
                    "audit_selected_button"):
            ui[name].configure(state=state)

    def _poll_queue(self):
        try:
            while True:
                key, kind, payload = self.msg_queue.get_nowait()
                ui = self._env[key]
                if kind == "log":
                    lt = ui["log_text"]
                    lt.configure(state="normal")
                    lt.insert("end", payload + "\n")
                    lt.see("end")
                    lt.configure(state="disabled")
                elif kind == "row":
                    ui["tree"].insert("", "end", values=(
                        payload["scenario"], payload["status"],
                        payload.get("request_number", ""), payload.get("cleanup_status", "…")))
                elif kind == "row_update":
                    for item in ui["tree"].get_children():
                        vals = list(ui["tree"].item(item, "values"))
                        if vals[0] == payload[0]:
                            vals[3] = payload[1]
                            ui["tree"].item(item, values=vals)
                elif kind == "tickets_loaded":
                    ui["tickets_tree"].delete(*ui["tickets_tree"].get_children())
                    ui["ticket_rows"].clear()
                    for ticket in payload:
                        item_id = ui["tickets_tree"].insert("", "end", values=(
                            ticket["ritm_number"], ticket["state"], ticket["created"],
                            ticket["short_description"]))
                        ui["ticket_rows"][item_id] = ticket
                elif kind == "ticket_state_update":
                    item_id, new_state = payload
                    if ui["tickets_tree"].exists(item_id):
                        vals = list(ui["tickets_tree"].item(item_id, "values"))
                        vals[1] = new_state
                        ui["tickets_tree"].item(item_id, values=vals)
                elif kind == "done":
                    ui["running"] = False
                    self._set_buttons_state(key, "normal")
                    ui["status_label"].configure(text="Listo")
                elif kind == "error":
                    messagebox.showerror("Error", payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    # ---------------------------------------------------------------- acciones ----

    def _on_run(self, key: str):
        ui = self._env[key]
        env = ui["env"]
        if ui["running"]:
            return

        selected = [name for name, var in ui["scenario_vars"].items() if var.get()]
        if not selected:
            messagebox.showwarning("Sin servicios", "Selecciona al menos un servicio a incluir en el ticket.")
            return

        if not self._has_connection(key):
            messagebox.showwarning("Conexión", "Configura la URL de instancia y el sys_id del catalog "
                                                "item en 'Conexión' antes de continuar.")
            return

        dry_run = ui["dry_run_var"].get()
        if not dry_run and not self._has_credentials(key):
            messagebox.showwarning("Credenciales", "Ingresa usuario+password o un token.")
            return

        if env.is_production and not dry_run:
            if not messagebox.askyesno(
                "⚠ Confirmar acción en PRODUCCIÓN",
                "Estás a punto de crear un ticket REAL en la instancia de PRODUCCIÓN de ServiceNow "
                f"({env.base_url}).\n\nServicios: {', '.join(selected)}\n\n¿Continuar?",
                icon="warning",
            ):
                return

        self._maybe_save_credentials(key)
        ui["tree"].delete(*ui["tree"].get_children())
        self._clear_log(key)

        ui["running"] = True
        self._set_buttons_state(key, "disabled")
        self._set_status(key, "Ejecutando…")

        ambiente = ui["ambiente_entry"].get().strip() or None
        app_name = ui["app_name_entry"].get().strip() or None
        descripcion = ui["descripcion_entry"].get().strip() or None
        solicitante_nombre = ui["solicitante_nombre_entry"].get().strip() or None
        solicitante_correo = ui["solicitante_correo_entry"].get().strip() or None
        solicitante_id = ui["solicitante_id_entry"].get().strip() or None
        cleanup = ui["cleanup_var"].get()
        auth, extra_headers = self._get_auth(key)

        overrides = {}
        for line in ui["overrides_text"].get("1.0", "end").splitlines():
            line = line.strip()
            if not line:
                continue
            if "=" not in line:
                self._log(key, f"Ignorando override mal formado (usa var=valor): {line}")
                continue
            k, v = line.split("=", 1)
            overrides[k.strip()] = v.strip()

        thread = threading.Thread(
            target=self._run_worker,
            args=(key, selected, auth, extra_headers, ambiente, app_name, descripcion,
                  solicitante_nombre, solicitante_correo, solicitante_id, overrides, dry_run, cleanup),
            daemon=True,
        )
        thread.start()

    def _run_worker(self, key, selected, auth, extra_headers, ambiente, app_name, descripcion,
                    solicitante_nombre, solicitante_correo, solicitante_id, overrides, dry_run, cleanup):
        env = self._env[key]["env"]
        label = "+".join(selected)
        self._log(key, f"[config] Ambiente ServiceNow: {env.label} ({env.base_url})")
        self._log(key, f"[config] Limpieza automática (cancelar al terminar): "
                       f"{'ACTIVADA' if cleanup else 'DESACTIVADA'}")
        payload = core.build_payload(selected, ambiente=ambiente, app_name=app_name,
                                     descripcion=descripcion, solicitante_id=solicitante_id,
                                     solicitante_nombre=solicitante_nombre,
                                     solicitante_correo=solicitante_correo, overrides=overrides)
        row = core.send_request(label, payload, auth, extra_headers, dry_run, log=lambda m, k=key: self._log(k, m),
                                base_url=env.base_url, sys_id=env.sys_id)
        results = [row]
        self.msg_queue.put((key, "row", row))

        if dry_run:
            self._log(key, "\n(dry-run: nada se envió ni se guardó en el log)")
            self.msg_queue.put((key, "done", None))
            return

        if cleanup:
            self._log(key, "\nLimpiando tickets de prueba...")
            core.cleanup_results(results, auth, extra_headers, log=lambda m, k=key: self._log(k, m),
                                 base_url=env.base_url, cancel_table=env.cancel_table,
                                 cancel_state_field=env.cancel_state_field,
                                 cancel_state_value=env.cancel_state_value)
            for row in results:
                self.msg_queue.put((key, "row_update", (row["scenario"], row.get("cleanup_status", ""))))
        else:
            for row in results:
                row["cleanup_status"] = "omitido"
                row["cleanup_error"] = ""
                self.msg_queue.put((key, "row_update", (row["scenario"], "omitido")))

        try:
            core.log_results(results, log_file=self._log_file_for(key))
            self._log(key, f"Resultados agregados a {self._log_file_for(key)}")
        except OSError as exc:
            self._log(key, f"No se pudo escribir el log CSV: {exc}")

        self.msg_queue.put((key, "done", None))

    def _on_inspect(self, key: str):
        ui = self._env[key]
        env = ui["env"]
        if ui["running"]:
            return
        if not self._has_connection(key):
            messagebox.showwarning("Conexión", "Configura la URL de instancia y el sys_id del catalog "
                                                "item en 'Conexión' antes de continuar.")
            return
        if not self._has_credentials(key):
            messagebox.showwarning("Credenciales", "Ingresa usuario+password o un token.")
            return

        self._maybe_save_credentials(key)
        ui["running"] = True
        self._set_buttons_state(key, "disabled")
        self._set_status(key, "Consultando variables…")
        auth, extra_headers = self._get_auth(key)

        def worker():
            self._log(key, f"--- Variables obligatorias configuradas en el catalog item ({env.sys_id}) ---")
            core.list_variables(auth, extra_headers, mandatory_only=True, log=lambda m, k=key: self._log(k, m),
                               base_url=env.base_url, sys_id=env.sys_id)
            self.msg_queue.put((key, "done", None))

        threading.Thread(target=worker, daemon=True).start()

    def _on_inspect_field(self, key: str):
        ui = self._env[key]
        env = ui["env"]
        if ui["running"]:
            return
        name = ui["inspect_field_entry"].get().strip()
        if not name:
            messagebox.showwarning("Campo", "Escribe el nombre de la variable a consultar.")
            return
        if not self._has_connection(key):
            messagebox.showwarning("Conexión", "Configura la URL de instancia y el sys_id del catalog "
                                                "item en 'Conexión' antes de continuar.")
            return
        if not self._has_credentials(key):
            messagebox.showwarning("Credenciales", "Ingresa usuario+password o un token.")
            return

        self._maybe_save_credentials(key)
        ui["running"] = True
        self._set_buttons_state(key, "disabled")
        self._set_status(key, f"Consultando '{name}'…")
        auth, extra_headers = self._get_auth(key)

        def worker():
            core.get_variable_detail(auth, extra_headers, name, log=lambda m, k=key: self._log(k, m),
                                     base_url=env.base_url, sys_id=env.sys_id)
            self.msg_queue.put((key, "done", None))

        threading.Thread(target=worker, daemon=True).start()

    def _on_refresh_tickets(self, key: str):
        ui = self._env[key]
        env = ui["env"]
        if ui["running"]:
            return
        if not self._has_connection(key):
            messagebox.showwarning("Conexión", "Configura la URL de instancia y el sys_id del catalog "
                                                "item en 'Conexión' antes de continuar.")
            return
        if not self._has_credentials(key):
            messagebox.showwarning("Credenciales", "Ingresa usuario+password o un token.")
            return

        try:
            limit = int(ui["ticket_limit_entry"].get().strip() or "25")
        except ValueError:
            limit = 25

        self._maybe_save_credentials(key)
        ui["running"] = True
        self._set_buttons_state(key, "disabled")
        self._set_status(key, "Consultando tickets…")
        auth, extra_headers = self._get_auth(key)

        def worker():
            tickets = core.list_recent_tickets(auth, extra_headers, limit=limit, log=lambda m, k=key: self._log(k, m),
                                              base_url=env.base_url, sys_id=env.sys_id)
            self.msg_queue.put((key, "tickets_loaded", tickets))
            self.msg_queue.put((key, "done", None))

        threading.Thread(target=worker, daemon=True).start()

    def _on_select_all_tickets(self, key: str):
        ui = self._env[key]
        ui["tickets_tree"].selection_set(ui["tickets_tree"].get_children())

    def _on_cancel_selected_tickets(self, key: str):
        ui = self._env[key]
        env = ui["env"]
        if ui["running"]:
            return
        selected = ui["tickets_tree"].selection()
        if not selected:
            messagebox.showwarning("Sin selección", "Selecciona al menos un ticket (Ctrl+clic para varios).")
            return
        if not self._has_credentials(key):
            messagebox.showwarning("Credenciales", "Ingresa usuario+password o un token.")
            return

        if env.is_production:
            confirm_msg = (f"⚠ PRODUCCIÓN: vas a cancelar {len(selected)} ticket(s) REALES en "
                           f"{env.base_url}.\n\nEsta acción no se puede deshacer desde aquí. ¿Continuar?")
        else:
            confirm_msg = (f"¿Cancelar {len(selected)} ticket(s) seleccionados? "
                          "Esta acción no se puede deshacer desde aquí.")
        if not messagebox.askyesno("Confirmar", confirm_msg, icon="warning"):
            return

        to_cancel = []
        for item_id in selected:
            ticket = ui["ticket_rows"].get(item_id)
            if ticket and ticket.get("request_sys_id"):
                to_cancel.append((item_id, ticket))
            elif ticket:
                self._log(key, f"  {ticket.get('ritm_number')}: sin sys_id de REQ, se omite.")

        ui["running"] = True
        self._set_buttons_state(key, "disabled")
        self._set_status(key, "Cancelando…")
        auth, extra_headers = self._get_auth(key)

        def worker():
            seen_req_sys_ids = set()
            for item_id, ticket in to_cancel:
                req_sys_id = ticket["request_sys_id"]
                if req_sys_id in seen_req_sys_ids:
                    continue
                seen_req_sys_ids.add(req_sys_id)
                result = core.cancel_request(req_sys_id, auth, extra_headers, log=lambda m, k=key: self._log(k, m),
                                             base_url=env.base_url, cancel_table=env.cancel_table,
                                             cancel_state_field=env.cancel_state_field,
                                             cancel_state_value=env.cancel_state_value)
                new_state = "cancelado" if result["cancelled"] else f"error: {result['cleanup_error'][:40]}"
                self.msg_queue.put((key, "ticket_state_update", (item_id, new_state)))
            self.msg_queue.put((key, "done", None))

        threading.Thread(target=worker, daemon=True).start()

    def _on_audit_selected_ticket(self, key: str):
        ui = self._env[key]
        env = ui["env"]
        if ui["running"]:
            return
        selected = ui["tickets_tree"].selection()
        if not selected:
            messagebox.showwarning("Sin selección", "Selecciona un ticket para auditar.")
            return
        if not self._has_credentials(key):
            messagebox.showwarning("Credenciales", "Ingresa usuario+password o un token.")
            return

        item_id = selected[0]
        ticket = ui["ticket_rows"].get(item_id)
        if not ticket:
            return

        self._maybe_save_credentials(key)
        ui["running"] = True
        self._set_buttons_state(key, "disabled")
        self._set_status(key, "Auditando…")
        auth, extra_headers = self._get_auth(key)

        def worker():
            if ticket.get("ritm_sys_id"):
                core.get_audit_history("sc_req_item", ticket["ritm_sys_id"], auth, extra_headers,
                                       log=lambda m, k=key: self._log(k, m), base_url=env.base_url)
            if ticket.get("request_sys_id"):
                self._log(key, "")
                core.get_audit_history("sc_request", ticket["request_sys_id"], auth, extra_headers,
                                       log=lambda m, k=key: self._log(k, m), base_url=env.base_url)
            self.msg_queue.put((key, "done", None))

        threading.Thread(target=worker, daemon=True).start()

    def _on_copy_request_number(self, key: str, event=None):
        ui = self._env[key]
        selected = ui["tree"].selection()
        if not selected:
            return
        request_numbers = []
        for item_id in selected:
            vals = ui["tree"].item(item_id, "values")
            req_number = vals[2] if len(vals) > 2 else ""
            if req_number:
                request_numbers.append(str(req_number))
        if not request_numbers:
            self._log(key, "(la fila seleccionada no tiene un Request # que copiar)")
            return
        text = "\n".join(request_numbers)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._log(key, f"Copiado al portapapeles: {', '.join(request_numbers)}")

    def _clear_log(self, key: str):
        lt = self._env[key]["log_text"]
        lt.configure(state="normal")
        lt.delete("1.0", "end")
        lt.configure(state="disabled")

    def _maximize_window(self):
        try:
            self.state("zoomed")
        except tk.TclError:
            try:
                self.attributes("-zoomed", True)
            except tk.TclError:
                self.geometry(f"{self.winfo_screenwidth()}x{self.winfo_screenheight()}+0+0")


def launch():
    app = ServiceNowTesterApp()
    app.mainloop()


if __name__ == "__main__":
    launch()
