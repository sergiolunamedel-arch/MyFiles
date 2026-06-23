from __future__ import annotations



import textwrap
import threading
import tkinter as tk
from tkinter import ttk

# Injected at startup by _wire_mixin_globals() — never assign here at load time.
T:      dict | None = None
_FUI:   str         = "Segoe UI"
_FMONO: str         = "Consolas"


def _wire_mixin_globals(**kw) -> None:
    g = globals()
    for k, v in kw.items():
        g[k] = v


_STEP_DOT_ACTIVE  = "●"
_STEP_DOT_DONE    = "✓"
_STEP_DOT_FUTURE  = "○"
_STEP_DOT_OMITTED = "–"

_WELCOME_TEXT = textwrap.dedent("""\
    Este asistente le guía a través de cada paso necesario para ejecutar
    su primer escaneo de seguridad y generar un reporte en aproximadamente dos minutos.

    Lo que cubriremos:

      1 · Autenticar con Snyk — iniciar sesión con el SSO de su organización
      2 · Seleccionar o crear un perfil de App — agrupa escaneos en el tiempo
      3 · Elegir etapas del escaneo — SCA y Análisis de código son recomendados
      4 · DAST (opcional) — análisis dinámico de una URL activa
      5 · Especificación API (opcional) — prueba cada endpoint en su documento OpenAPI
      6 · Ejecutar el escaneo — los resultados aparecen en la consola y se guarda un reporte

    ¡Comencemos — haga clic en "Siguiente" para empezar!
""")


# ══════════════════════════════════════════════════════════════════════════════
# Mixin — public API attached to ScannerApp
# ══════════════════════════════════════════════════════════════════════════════

class _WizardMixin:

    def open_wizard(self) -> None:
        existing = getattr(self, "_wizard_win", None)
        if existing and existing.winfo_exists():
            existing.lift(); existing.focus_force(); return
        # Same 0.75×0.75 as every other popup — the scrollable content area
        # handles any overflow, so no custom size is needed here.
        popup = self._create_popup("Asistente de configuración", 0.75, 0.75)
        self._wizard_win = popup._win
        _WizardWindow(self, popup)

    # ── State queries (also used by step validators) ──────────────────────

    def _wiz_check_auth(self) -> tuple[bool, str]:
        status = getattr(self, "_key_auth_status", "checking")
        if status == "auth":     return True,  "Autenticado mediante SSO ✓"
        if status == "checking": return False, "Verificando sesión SSO…"
        return False, "No autenticado — inicie sesión SSO a continuación."

    def _wiz_check_app(self) -> tuple[bool, str]:
        app = getattr(self, "_active_app", None)
        if app and app.get("name"): return True, f"App cargada: {app['name']}"
        return False, "Sin app cargada — cree o seleccione una a continuación."

    def _wiz_check_stages(self) -> tuple[bool, str]:
        scan_vars = getattr(self, "_scan_vars", {})
        enabled = [k for k, v in scan_vars.items() if v.get()]
        if enabled: return True, "Etapas seleccionadas: " + ", ".join(enabled).upper()
        return False, "Seleccione al menos una etapa de escaneo."

    def _wiz_check_dast(self) -> tuple[bool, str]:
        try:
            url = (getattr(self, "_dast_url_var", None) or tk.StringVar()).get().strip()
        except Exception:
            url = ""
        return (True, f"DAST URL: {url}") if url else \
               (False, "Sin URL DAST (opcional — haga clic en Omitir para saltar).")

    def _wiz_check_api(self) -> tuple[bool, str]:
        try:
            spec = (getattr(self, "_api_spec_var", None) or tk.StringVar()).get().strip()
        except Exception:
            spec = ""
        return (True, f"Especificación API: {spec}") if spec else \
               (False, "Sin especificación API (opcional — haga clic en Omitir para saltar).")


# ══════════════════════════════════════════════════════════════════════════════
# Wizard UI — built inside an app._create_popup() content frame
# ══════════════════════════════════════════════════════════════════════════════

class _WizardWindow:
    

    _STEPS = [
        ("Bienvenido",      False, "_build_step_welcome"),
        ("Autenticación Snyk",    False, "_build_step_auth"),
        ("Perfil de app",  False, "_build_step_app"),
        ("Etapas de escaneo",  False, "_build_step_stages"),
        ("Config DAST",  True,  "_build_step_dast"),
        ("Especificación API",     True,  "_build_step_api"),
        ("Ejecutar y reportar", False, "_build_step_run"),
    ]

    def __init__(self, app, popup: tk.Frame) -> None:
        self._app    = app
        self._popup  = popup
        self._win    = popup._win
        self._step   = 0
        self._omitted: set[int] = set()
        self._build_chrome()
        self._render_step(0)

    # ─────────────────────────────────────────────────────────────────────
    # Chrome

    def _build_chrome(self) -> None:
        # ── Standard popup header ─────────────────────────────────────────
        # on_close → shows a confirm dialog before destroying, same pattern
        # as any destructive action in the app.
        hdr = self._app._popup_hdr(
            self._popup, "Asistente de configuración",
            icon="🛡", on_close=self._on_close,
        )
        # Step counter packed into the shared header row, left of the ✕.
        self._hdr_step_lbl = tk.Label(
            hdr._row, text="", font=(_FUI, 9),
            bg=T["panel_bg"], fg=T["muted"],
        )
        self._hdr_step_lbl.pack(side="right", padx=(0, 10))

        # Drag support — bind to the header frame so the user can reposition.
        self._drag_x = self._drag_y = 0
        for target in (hdr, hdr._row):
            target.bind("<ButtonPress-1>", self._drag_start)
            target.bind("<B1-Motion>",     self._drag_move)

        # ── Step ribbon ───────────────────────────────────────────────────
        self._ribbon_frame = tk.Frame(self._popup, bg=T["panel_bg"])
        self._ribbon_frame.pack(fill="x")
        self._build_ribbon()

        # ── Scrollable content area ───────────────────────────────────────
        self._content_outer = tk.Frame(self._popup, bg=T["bg"])
        self._content_outer.pack(fill="both", expand=True)

        # ── Footer navigation ─────────────────────────────────────────────
        tk.Frame(self._popup, bg=T["border_bg"], height=1).pack(fill="x")
        footer = tk.Frame(self._popup, bg=T["panel_bg"], height=56)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        # Status/validation message on the left
        self._status_var = tk.StringVar(value="")
        tk.Label(
            footer, textvariable=self._status_var,
            font=(_FUI, 9), bg=T["panel_bg"], fg=T["muted"], anchor="w",
        ).pack(side="left", padx=20, fill="x", expand=True)

        # Navigation buttons on the right — same _btn kinds used everywhere
        nav = tk.Frame(footer, bg=T["panel_bg"])
        nav.pack(side="right", padx=16, pady=12)
        self._btn_omit = self._app._btn(nav, "Omitir",        self._do_omit, "flat")
        self._btn_omit.pack(side="left", padx=(0, 6))
        self._btn_prev = self._app._btn(nav, "◀  Anterior",  self._do_prev, "flat")
        self._btn_prev.pack(side="left", padx=(0, 6))
        self._btn_next = self._app._btn(nav, "Siguiente  ▶",      self._do_next, "accent")
        self._btn_next.pack(side="left")

    def _drag_start(self, event) -> None:
        self._drag_x = event.x_root - self._win.winfo_x()
        self._drag_y = event.y_root - self._win.winfo_y()

    def _drag_move(self, event) -> None:
        self._win.geometry(
            f"+{event.x_root - self._drag_x}+{event.y_root - self._drag_y}")

    # ─────────────────────────────────────────────────────────────────────
    # Step ribbon

    def _build_ribbon(self) -> None:
        for w in self._ribbon_frame.winfo_children():
            w.destroy()
        # Border separator at bottom of ribbon
        separator = tk.Frame(self._ribbon_frame, bg=T["border_bg"], height=1)
        separator.pack(side="bottom", fill="x")
        inner = tk.Frame(self._ribbon_frame, bg=T["panel_bg"])
        inner.pack(fill="x", padx=8, pady=(6, 4))
        total = len(self._STEPS)
        _label_refs = []  # keep refs to update wraplength on resize
        for i, (title, _, _b) in enumerate(self._STEPS):
            done    = (i < self._step) and (i not in self._omitted)
            omitted = i in self._omitted
            active  = i == self._step
            if done:      dot, color = _STEP_DOT_DONE,    T["ok"]
            elif omitted: dot, color = _STEP_DOT_OMITTED, T["muted"]
            elif active:  dot, color = _STEP_DOT_ACTIVE,  T["accent"]
            else:         dot, color = _STEP_DOT_FUTURE,  T["muted"]
            cell = tk.Frame(inner, bg=T["panel_bg"])
            cell.pack(side="left", expand=True, fill="x")
            tk.Label(cell, text=dot, font=(_FUI, 11),
                     bg=T["panel_bg"], fg=color).pack()
            lbl = tk.Label(cell, text=title,
                     font=(_FUI, 8 if not active else 9,
                            "normal" if not active else "bold"),
                     bg=T["panel_bg"], fg=color,
                     wraplength=100, justify="center")
            lbl.pack(fill="x")
            _label_refs.append((cell, lbl))
            if i < total - 1:
                tk.Label(inner, text="›", font=(_FUI, 12),
                         bg=T["panel_bg"], fg=T["border"]).pack(side="left")

        def _update_wraplengths(e=None):
            # Distribute available width evenly across step cells
            available = inner.winfo_width()
            if available < 10:
                return
            # Approximate: total width minus separator arrows (total-1 arrows × ~16px)
            cell_w = max(60, (available - (total - 1) * 18) // total - 4)
            for cell, lbl in _label_refs:
                lbl.config(wraplength=cell_w)

        inner.bind("<Configure>", _update_wraplengths)

    # ─────────────────────────────────────────────────────────────────────
    # Step rendering

    def _render_step(self, idx: int) -> None:
        self._step = idx
        self._build_ribbon()
        self._hdr_step_lbl.config(
            text=f"Paso {idx + 1} de {len(self._STEPS)}"
                 + ("  (opcional)" if self._STEPS[idx][1] else ""),
        )
        for w in self._content_outer.winfo_children():
            w.destroy()

        canvas = tk.Canvas(self._content_outer, bg=T["bg"],
                           highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(self._content_outer, orient="vertical",
                            command=canvas.yview)
        self._content_frame = tk.Frame(canvas, bg=T["bg"])
        win_id = canvas.create_window((0, 0), window=self._content_frame, anchor="nw")

        def _recentre(e=None):
            cw = canvas.winfo_width()
            if cw > 1:
                # Always fill the full canvas width — no centering offset
                canvas.itemconfig(win_id, width=cw)
            canvas.configure(scrollregion=canvas.bbox("all"))

        self._content_frame.bind("<Configure>", _recentre)
        canvas.bind("<Configure>", _recentre)
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        canvas.bind_all(
            "<MouseWheel>",
            lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"),
        )

        getattr(self, self._STEPS[idx][2])(self._content_frame)
        self._refresh_nav()

    # ─────────────────────────────────────────────────────────────────────
    # Navigation state

    def _refresh_nav(self) -> None:
        idx   = self._step
        last  = idx == len(self._STEPS) - 1
        first = idx == 0
        self._btn_prev.config(
            state="normal" if not first else "disabled",
            fg=T["text"] if not first else T["muted"],
        )
        if self._STEPS[idx][1] and not first and not last:
            self._btn_omit.config(state="normal",   fg=T["muted"])
        else:
            self._btn_omit.config(state="disabled", fg=T["bg"])
        if last:
            self._btn_next.config(
                text="Finalizar  ✓", bg=T["ok"],
                fg=T.get("button_fg", "#000000"),
            )
        else:
            self._btn_next.config(text="Siguiente  ▶", bg=T["accent"], fg="#FFFFFF")

    def _do_next(self) -> None:
        idx = self._step
        if idx == len(self._STEPS) - 1:
            self._on_finish(); return
        ok, msg = self._validate_step(idx)
        if not ok:
            self._set_status(msg, error=True)
            self._flash_next_invalid()
            return
        self._set_status("")
        self._omitted.discard(idx)
        self._render_step(idx + 1)

    def _do_prev(self) -> None:
        if self._step > 0:
            self._set_status("")
            self._render_step(self._step - 1)

    def _do_omit(self) -> None:
        idx = self._step
        if not self._STEPS[idx][1]: return
        self._omitted.add(idx)
        self._set_status("")
        self._render_step(idx + 1)

    def _on_finish(self) -> None:
        self._popup.close()
        try: self._app._log_line("[wizard] Asistente completado.")
        except Exception: pass

    def _on_close(self) -> None:
        try: self._win.grab_release()
        except Exception: pass
        self._app._show_confirm_popup(
            "¿Cerrar asistente?",
            "¿Cerrar el asistente de configuración?\n\n"
            "Puede reabrirlo en cualquier momento desde el botón 🧙 en la barra de herramientas.",
            on_yes=self._popup.close,
            yes_label="  Sí, cerrar  ",
            no_label="  Mantener abierto  ",
        )

    def _validate_step(self, idx: int) -> tuple[bool, str]:
        name = self._STEPS[idx][2]
        if name == "_build_step_welcome": return True, ""
        if name == "_build_step_auth":    return self._app._wiz_check_auth()
        if name == "_build_step_app":     return self._app._wiz_check_app()
        if name == "_build_step_stages":  return self._app._wiz_check_stages()
        return True, ""

    def _set_status(self, msg: str, *, error: bool = False) -> None:
        self._status_var.set(msg)
        # status Label is the first child of footer (packed left, expand=True)
        footer = self._btn_next.master.master
        for w in footer.winfo_children():
            if isinstance(w, tk.Label):
                w.config(fg=T["err"] if error else T["muted"])
                break

    def _flash_next_invalid(self) -> None:
        self._btn_next.config(bg=T["err"])
        self._win.after(350, lambda: self._btn_next.config(bg=T["accent"]))

    # ─────────────────────────────────────────────────────────────────────
    # Layout helpers — shared across all step builders

    def _section(self, parent, text: str) -> tk.Frame:

        frame = tk.Frame(parent, bg=T["panel_bg"],
                         highlightbackground=T["border"], highlightthickness=1)
        frame.pack(fill="x", padx=16, pady=(0, 12))
        tk.Label(frame, text=text.upper(), font=(_FUI, 8, "bold"),
                 bg=T["panel_bg"], fg=T["accent"], anchor="w").pack(
                     fill="x", padx=12, pady=(10, 4))
        body = tk.Frame(frame, bg=T["panel_bg"])
        body.pack(fill="x", padx=12, pady=(0, 10))
        return body

    def _body_text(self, parent, text: str, *, fg: str | None = None) -> None:
        lbl = tk.Label(parent, text=text, font=(_FUI, 10),
                 bg=T["bg"], fg=fg or T["text"],
                 justify="left", anchor="w", wraplength=540)
        lbl.pack(fill="x", padx=16, pady=(0, 8))
        def _resize(e, l=lbl): l.config(wraplength=max(200, e.width - 36))
        lbl.bind("<Configure>", _resize)

    def _status_row(self, parent, ok: bool, msg: str) -> None:
        color = T["ok"] if ok else T["err"]
        row   = tk.Frame(parent, bg=T["panel_bg"])
        row.pack(fill="x")
        tk.Label(row, text="✓" if ok else "✗", font=(_FUI, 11, "bold"),
                 bg=T["panel_bg"], fg=color, width=2).pack(side="left")
        lbl = tk.Label(row, text=msg, font=(_FUI, 10),
                 bg=T["panel_bg"], fg=color,
                 anchor="w", wraplength=480)
        lbl.pack(side="left", fill="x", expand=True)
        def _resize(e, l=lbl): l.config(wraplength=max(200, e.width - 8))
        lbl.bind("<Configure>", _resize)

    def _inline_btn(self, parent, label: str, cmd, kind: str = "accent") -> None:

        self._app._btn(parent, label, cmd, kind).pack(anchor="w", pady=(8, 0))

    def _field_row(self, parent, label: str, var: tk.StringVar,
                   *, readonly: bool = False) -> ttk.Entry:

        row = tk.Frame(parent, bg=T["panel_bg"])
        row.pack(fill="x", pady=(4, 0))
        tk.Label(row, text=label, font=(_FUI, 9),
                 bg=T["panel_bg"], fg=T["muted"], width=16, anchor="w").pack(side="left")
        e = ttk.Entry(row, textvariable=var,
                      state="readonly" if readonly else "normal")
        e.pack(side="left", fill="x", expand=True)
        return e

    # ─────────────────────────────────────────────────────────────────────
    # Step 0 — Welcome

    def _build_step_welcome(self, parent: tk.Frame) -> None:
        # Accent hero banner — gives the first step immediate visual weight.
        hero = tk.Frame(parent, bg=T["accent"])
        hero.pack(fill="x")
        tk.Label(hero, text="👋  Bienvenido a Snyk Scanner",
                 font=(_FUI, 16, "bold"), bg=T["accent"], fg="#FFFFFF").pack(
                     pady=(20, 4), padx=16, anchor="w")
        tk.Label(hero, text="Configuremos juntos su primer escaneo de seguridad.",
                 font=(_FUI, 11), bg=T["accent"], fg="#FFFFFF").pack(
                     pady=(0, 16), padx=16, anchor="w")

        # Welcome body
        for line in _WELCOME_TEXT.strip().splitlines():
            mono = line.startswith("  ")
            tk.Label(parent, text=line,
                     font=(_FMONO if mono else _FUI, 10),
                     bg=T["bg"],
                     fg=T["accent"] if mono else T["text"],
                     anchor="w", justify="left").pack(
                         fill="x", padx=16, pady=(2 if mono else 0, 0))

    # ─────────────────────────────────────────────────────────────────────
    # Step 1 — Snyk Auth

    def _build_step_auth(self, parent: tk.Frame) -> None:
        ok, msg = self._app._wiz_check_auth()
        launching = getattr(self, "_auth_launching", False)

        card = tk.Frame(parent, bg=T["panel_bg"],
                        highlightbackground=T["border"], highlightthickness=1)
        card.pack(fill="both", expand=True, padx=16, pady=12)

        # Logo column
        import sys, pathlib
        _img_ref = [None]
        left = tk.Frame(card, bg=T["panel_bg"])
        left.pack(side="left", padx=(12, 8), pady=16, anchor="n")
        try:
            main_mod   = sys.modules.get("__main__", None)
            script_dir = pathlib.Path(getattr(main_mod, "__file__", "") or "").parent
            img_path   = script_dir / "Snyk.png"
            if not img_path.exists():
                img_path = pathlib.Path(__file__).parent / "Snyk.png"
            if img_path.exists():
                _img_ref[0] = tk.PhotoImage(file=str(img_path))
                w, h = _img_ref[0].width(), _img_ref[0].height()
                factor = max(1, max(w // 200, h // 200))
                if factor > 1:
                    _img_ref[0] = _img_ref[0].subsample(factor, factor)
                lbl = tk.Label(left, image=_img_ref[0], bg=T["panel_bg"],
                               highlightthickness=1, highlightbackground=T["border"])
                lbl.image = _img_ref[0]
                lbl.pack()
        except Exception:
            tk.Label(left, text="🔑", font=(_FUI, 36),
                     bg=T["panel_bg"], fg=T["accent"]).pack()

        # Instructions column — fills all remaining space
        right = tk.Frame(card, bg=T["panel_bg"])
        right.pack(side="left", fill="both", expand=True, padx=(0, 12), pady=16)

        tk.Label(right, text="ℹ️  Debe iniciar sesión con SSO",
                 font=(_FUI, 11, "bold"), bg=T["panel_bg"], fg=T["accent"],
                 anchor="w").pack(fill="x", pady=(0, 8))

        instr_lbl = tk.Label(right,
                 text=("Su navegador se abrirá en un momento.\n\n"
                       "En la ventana de Snyk que aparece:\n\n"
                       "  1. Click 'Log in with your company SSO'\n"
                       "     — NOT Google or username/password.\n"
                       "  2. Ingrese el dominio de su organización cuando se le solicite.\n"
                       "  3. Complete the authentication in the browser.\n"
                       "  4. Return here — status updates automatically."),
                 font=(_FUI, 10), bg=T["panel_bg"], fg=T["text"],
                 justify="left", anchor="w", wraplength=400)
        instr_lbl.pack(fill="x")
        def _resize_instr(e, l=instr_lbl): l.config(wraplength=max(200, e.width - 4))
        instr_lbl.bind("<Configure>", _resize_instr)

        tk.Frame(right, bg=T["border_bg"], height=1).pack(fill="x", pady=(10, 8))
        self._status_row(right, ok, msg)

        # ── Loading spinner (shown while browser is launching) ────────────
        if launching and not ok:
            _DOTS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            _idx = [0]
            loading_lbl = tk.Label(
                right,
                text=f"{_DOTS[0]}  Cargando navegador, puede tomar hasta 30 segundos…",
                font=(_FUI, 10), bg=T["panel_bg"], fg=T["accent"],
                anchor="w",
            )
            loading_lbl.pack(anchor="w", pady=(10, 0))
            hint_lbl = tk.Label(
                right,
                text="Complete el inicio de sesión SSO en su navegador.\n"
                     "Esta pantalla se actualizará automáticamente al autenticarse.",
                font=(_FUI, 9), bg=T["panel_bg"], fg=T["muted"],
                anchor="w", justify="left", wraplength=400,
            )
            hint_lbl.pack(anchor="w", pady=(4, 0))
            def _resize_hint(e, l=hint_lbl): l.config(wraplength=max(200, e.width - 4))
            hint_lbl.bind("<Configure>", _resize_hint)

            def _spin():
                try:
                    if not loading_lbl.winfo_exists():
                        return
                except Exception:
                    return
                if not getattr(self, "_auth_launching", False):
                    return
                _idx[0] = (_idx[0] + 1) % len(_DOTS)
                loading_lbl.config(
                    text=f"{_DOTS[_idx[0]]}  Cargando navegador, puede tomar hasta 30 segundos…"
                )
                self._win.after(100, _spin)

            self._win.after(100, _spin)

        # ── Normal button row (shown when idle or already authed) ─────────
        else:
            btn_row = tk.Frame(right, bg=T["panel_bg"])
            btn_row.pack(anchor="w", pady=(10, 0))
            if not ok:
                self._app._btn(btn_row, "🔑  Iniciar sesión SSO",
                               self._do_sso_login, "accent").pack(side="left")
            else:
                self._app._btn(btn_row, "🔁  Reiniciar sesión (SSO)",
                               self._do_sso_login, "flat").pack(side="left")
                tk.Label(right,
                         text="Haga clic en Siguiente para continuar — su sesión SSO está activa.",
                         font=(_FUI, 9), bg=T["panel_bg"], fg=T["muted"],
                         anchor="w").pack(fill="x", pady=(6, 0))

    def _do_sso_login(self) -> None:
        """Lanza el navegador para autenticación SSO directamente, mostrando
        un spinner en el paso actual. No abre ningún panel secundario."""
        self._auth_launching = True
        self._render_step(self._step)   # re-renderiza para mostrar spinner

        # ── Hook en el callback de auth_check_done ────────────────────────
        # _drain_events llama a _login_popup_close cuando el proceso de auth
        # completa con ok=True. Nos enganchamos aquí para auto-refrescar el paso.
        _prev_close = getattr(self._app, "_login_popup_close", None)

        def _on_auth_complete():
            self._auth_launching = False
            if callable(_prev_close):
                try: _prev_close()
                except Exception: pass
            if self._win.winfo_exists() and self._step == 1:
                self._render_step(self._step)

        self._app._login_popup_close = _on_auth_complete

        # ── Lanzar navegador vía start_snyk_auth en hilo de fondo ─────────
        def _run():
            try:
                _fn = globals().get("start_snyk_auth")
                if _fn is None:
                    # Fallback mínimo: abrir Snyk directamente con webbrowser
                    import webbrowser as _wb
                    _wb.open("https://app.snyk.io/login?redirectUri=/")
                    return
                proc = _fn(self._app._emit_log)
                # Registrar el proceso para que _tick_auth_poll lo monitoree
                if proc is not None and hasattr(self._app, "_auth_proc"):
                    self._app._auth_proc = proc
            except Exception as exc:
                try: self._app._emit_log(f"[wizard-auth] Error al lanzar navegador: {exc}")
                except Exception: pass

        threading.Thread(target=_run, daemon=True).start()
        self._poll_auth_status()

    def _poll_auth_status(self) -> None:
        """Revisa _key_auth_status cada segundo y refresca el paso de auth
        cuando Snyk confirma el inicio de sesión. Complementa _login_popup_close
        como mecanismo de respaldo (belt-and-suspenders)."""
        if not getattr(self, "_auth_launching", False):
            return
        if not self._win.winfo_exists():
            return
        if getattr(self._app, "_key_auth_status", "checking") == "auth":
            self._auth_launching = False
            if self._step == 1:
                self._render_step(self._step)
            return
        self._win.after(1000, self._poll_auth_status)



    # ─────────────────────────────────────────────────────────────────────
    # Step 2 — App Profile

    def _build_step_app(self, parent: tk.Frame) -> None:
        ok, msg = self._app._wiz_check_app()
        self._body_text(parent,
            "Un Perfil de App agrupa su objetivo, configuración e historial de vulnerabilidades "
            "para rastrear resultados en el tiempo y compararlos entre escaneos.")

        sec = self._section(parent, "Perfil de aplicación actual")
        self._status_row(sec, ok, msg)
        if ok:
            app = getattr(self._app, "_active_app", {}) or {}
            for lbl, val in [
                ("Nombre",              app.get("name",        "—")),
                ("Tipo",              app.get("app_type",    "—")),
                ("Criticidad de negocio", app.get("criticality", "—")),
                ("Ruta objetivo",       app.get("target_path", "—") or "—"),
                ("DAST URL",          app.get("dast_url",    "—") or "—"),
            ]:
                row = tk.Frame(sec, bg=T["panel_bg"])
                row.pack(fill="x", pady=1)
                tk.Label(row, text=f"{lbl}:", font=(_FUI, 9),
                         bg=T["panel_bg"], fg=T["muted"],
                         width=18, anchor="w").pack(side="left")
                val_lbl = tk.Label(row, text=val, font=(_FUI, 9),
                         bg=T["panel_bg"], fg=T["text"],
                         anchor="w", wraplength=380)
                val_lbl.pack(side="left", fill="x", expand=True)
                def _rv(e, l=val_lbl): l.config(wraplength=max(150, e.width - 4))
                val_lbl.bind("<Configure>", _rv)

        sec2 = self._section(parent, "Cambiar perfil")
        self._inline_btn(sec2, "📦  Abrir inventario de aplicaciones", self._open_app_inventory)
        _hint = tk.Label(sec2,
                 text="Seleccione o cree una app allí, luego haga clic en '▶ Cargar en el escáner'.\n"
                      "Regrese a este asistente — su selección se reflejará aquí.",
                 font=(_FUI, 9), bg=T["panel_bg"], fg=T["muted"],
                 justify="left", anchor="w", wraplength=480)
        _hint.pack(fill="x", pady=(4, 0))
        def _rh(e, l=_hint): l.config(wraplength=max(200, e.width - 4))
        _hint.bind("<Configure>", _rh)

    def _open_app_inventory(self) -> None:
        try: self._app._show_tab("apps")
        except Exception: pass
        try: self._win.grab_release()
        except Exception: pass
        self._win.iconify()
        self._inject_return_chip()

    def _inject_return_chip(self) -> None:
        old = getattr(self, "_return_chip", None)
        if old:
            try: old.destroy()
            except Exception: pass
        chip = tk.Toplevel(self._app)
        chip.overrideredirect(True)
        chip.attributes("-topmost", True)
        chip.configure(bg=T["accent"])
        px = self._app.winfo_x() + self._app.winfo_width()  - 232
        py = self._app.winfo_y() + self._app.winfo_height() - 62
        chip.geometry(f"220x38+{px}+{py}")
        def _return():
            chip.destroy()
            if self._win.winfo_exists():
                self._win.deiconify(); self._win.grab_set()
                self._win.lift();      self._win.focus_force()
                self._render_step(self._step)
        tk.Button(chip, text="🧙  Volver al asistente",
                  font=(_FUI, 10, "bold"), bg=T["accent"], fg="#FFFFFF",
                  relief="flat", cursor="hand2", command=_return).pack(
                      fill="both", expand=True, padx=2, pady=2)
        self._return_chip = chip

    # ─────────────────────────────────────────────────────────────────────
    # Step 3 — Scan Stages

    def _build_step_stages(self, parent: tk.Frame) -> None:
        self._body_text(parent,
            "Elija qué etapas de análisis ejecutar. Cada etapa apunta a un tipo diferente "
            "layer of your application.  SCA and Code Analysis are recommended for all apps.")

        sec = self._section(parent, "Selección de etapas")
        scan_vars: dict[str, tk.BooleanVar] = getattr(self._app, "_scan_vars", {})
        if not scan_vars:
            tk.Label(sec, text="⚠  scan_vars no encontrado — verifique el cableado de la interfaz.",
                     font=(_FUI, 9), bg=T["panel_bg"], fg=T["err"]).pack(anchor="w")
            return

        _STAGE_META = {
            "sca":   ("📦  SCA",          "Vulnerabilidades en dependencias de código abierto"),
            "code":  ("🔍  Análisis de código", "Análisis de código estático (Snyk Code)"),
            "iac":   ("🏗  IaC",           "Configuraciones incorrectas de Infraestructura como Código"),
            "dast":  ("🌐  DAST",          "Análisis dinámico — requiere una URL activa"),
            "api":   ("🔌  Seguridad de API",  "Escaneo a nivel de API — requiere una especificación"),
            "image": ("🐳  Contenedor",     "Escaneo de vulnerabilidades en imágenes Docker"),
        }
        stage_status = tk.Frame(sec, bg=T["panel_bg"])
        for key, var in scan_vars.items():
            label, desc = _STAGE_META.get(key, (key.upper(), ""))
            row = tk.Frame(sec, bg=T["panel_bg"])
            row.pack(fill="x", pady=3)
            ttk.Checkbutton(
                row, variable=var,
                command=lambda: self._refresh_stage_status(stage_status),
            ).pack(side="left")
            col = tk.Frame(row, bg=T["panel_bg"])
            col.pack(side="left", padx=6)
            tk.Label(col, text=label, font=(_FUI, 10, "bold"),
                     bg=T["panel_bg"], fg=T["text"]).pack(anchor="w")
            if desc:
                tk.Label(col, text=desc, font=(_FUI, 9),
                         bg=T["panel_bg"], fg=T["muted"]).pack(anchor="w")
        stage_status.pack(fill="x", pady=(8, 0))
        self._refresh_stage_status(stage_status)

    def _refresh_stage_status(self, frame: tk.Frame) -> None:
        for w in frame.winfo_children():
            w.destroy()
        ok, msg = self._app._wiz_check_stages()
        self._status_row(frame, ok, msg)

    # ─────────────────────────────────────────────────────────────────────
    # Step 4 — DAST Config (optional)

    def _build_step_dast(self, parent: tk.Frame) -> None:
        ok, msg = self._app._wiz_check_dast()
        self._body_text(parent,
            "DAST (Dynamic Application Security Testing) probes your running application "
            "for vulnerabilities that only appear at runtime — injection flaws, auth "
            "issues, and more.\n\n"
            "Este asistente usa DAST con Selenium (no rastreo automático), así puede personalizar "
            "the exact user journeys you want tested.")

        sec = self._section(parent, "URL del objetivo")
        dast_url_var = getattr(self._app, "_dast_url_var", None)
        if dast_url_var is None:
            tk.Label(sec, text="⚠  _dast_url_var no encontrado.",
                     font=(_FUI, 9), bg=T["panel_bg"], fg=T["err"]).pack(anchor="w")
        else:
            self._field_row(sec, "URL de la aplicación", dast_url_var)

        sec2 = self._section(parent, "Script de Selenium")
        selenium_var = getattr(self._app, "_dast_selenium_script_var", None)
        if selenium_var is None:
            if not hasattr(self, "_wiz_selenium_var"):
                self._wiz_selenium_var = tk.StringVar(value="")
            selenium_var = self._wiz_selenium_var
        self._field_row(sec2, "Ruta del script", selenium_var)

        def _browse_script():
            from tkinter import filedialog
            p = filedialog.askopenfilename(
                title="Seleccionar script de Selenium",
                filetypes=[("Scripts Python", "*.py"), ("Todos los archivos", "*.*")],
                parent=self._win)
            if p:
                selenium_var.set(p)
                live = getattr(self._app, "_dast_selenium_script_var", None)
                if live is not None: live.set(p)
        self._inline_btn(sec2, "📂  Explorar…", _browse_script, "outline")
        _dast_hint = tk.Label(sec2,
                 text="The script is run by the DAST engine via Selenium WebDriver.\n"
                      "It should log in, navigate, and exercise the flows you want tested.\n"
                      "Déjelo en blanco para usar el script guardado previamente de la app (si existe).",
                 font=(_FUI, 9), bg=T["panel_bg"], fg=T["muted"],
                 justify="left", anchor="w", wraplength=480)
        _dast_hint.pack(fill="x", pady=(6, 0))
        def _rdh(e, l=_dast_hint): l.config(wraplength=max(200, e.width - 4))
        _dast_hint.bind("<Configure>", _rdh)

        sec3 = self._section(parent, "Modo DAST")
        tk.Label(sec3, text="Modo:  Selenium (basado en script)  ·  NO auto-crawl",
                 font=(_FMONO, 10), bg=T["panel_bg"], fg=T["accent"]).pack(anchor="w")
        tk.Label(sec3,
                 text="El auto-crawl puede habilitarse por separado en la pestaña DAST después del asistente.",
                 font=(_FUI, 9), bg=T["panel_bg"], fg=T["muted"],
                 justify="left", anchor="w").pack(anchor="w", pady=(4, 0))

        self._status_row(self._section(parent, "Estado"), ok, msg)

    # ─────────────────────────────────────────────────────────────────────
    # Step 5 — API Spec (optional)

    def _build_step_api(self, parent: tk.Frame) -> None:
        ok, msg = self._app._wiz_check_api()
        self._body_text(parent,
            "Provide an OpenAPI / Swagger spec to enable API-level security scanning.  "
            "El motor enviará peticiones de prueba a cada endpoint definido en la especificación y reportará "
            "OWASP API Top-10 findings.\n\n"
            "Este paso es opcional — haga clic en Omitir si su app no tiene especificación API.")

        sec = self._section(parent, "Ruta o URL de la especificación API")
        api_spec_var = getattr(self._app, "_api_spec_var", None)
        if api_spec_var is None:
            tk.Label(sec, text="⚠  _api_spec_var no encontrado.",
                     font=(_FUI, 9), bg=T["panel_bg"], fg=T["err"]).pack(anchor="w")
        else:
            self._field_row(sec, "Especificación", api_spec_var)
            def _browse_spec():
                from tkinter import filedialog
                p = filedialog.askopenfilename(
                    title="Seleccionar especificación API",
                    filetypes=[("OpenAPI / Swagger", "*.yaml *.yml *.json"),
                                ("Todos los archivos", "*.*")],
                    parent=self._win)
                if p: api_spec_var.set(p)
            self._inline_btn(sec, "📂  Explorar…", _browse_spec, "outline")

        self._status_row(self._section(parent, "Estado"), ok, msg)

    # ─────────────────────────────────────────────────────────────────────
    # Step 6 — Run & Report

    def _build_step_run(self, parent: tk.Frame) -> None:
        auth_ok,   auth_msg   = self._app._wiz_check_auth()
        app_ok,    app_msg    = self._app._wiz_check_app()
        stages_ok, stages_msg = self._app._wiz_check_stages()
        dast_ok,   dast_msg   = self._app._wiz_check_dast()
        api_ok,    api_msg    = self._app._wiz_check_api()
        dast_omitted = 4 in self._omitted
        api_omitted  = 5 in self._omitted

        self._body_text(parent,
            "Review your configuration below, then click 'Run Scan' to start.  "
            "The wizard will close and progress will appear in the main console.")

        sec = self._section(parent, "Resumen de configuración")
        self._status_row(sec, auth_ok,   f"Auth:       {auth_msg}")
        self._status_row(sec, app_ok,    f"App:        {app_msg}")
        self._status_row(sec, stages_ok, f"Etapas:     {stages_msg}")
        self._status_row(
            sec,
            True if dast_omitted else dast_ok,
            "DAST:    omitido" if dast_omitted else f"DAST:    {dast_msg}",
        )
        self._status_row(
            sec,
            True if api_omitted else api_ok,
            "API:        omitido" if api_omitted  else f"API:        {api_msg}",
        )

        ready = auth_ok and app_ok and stages_ok
        if not ready:
            self._body_text(parent,
                "⚠  Some required steps are not complete.  Go back and fix them "
                "before running the scan.", fg=T["err"])

        sec2 = self._section(parent, "Iniciar")
        if ready:
            self._inline_btn(sec2, "🚀  Ejecutar escaneo ahora", self._do_run_scan)
            _run_hint = tk.Label(sec2,
                     text="The wizard will close and the scan will start in the main window.\n"
                          "Monitor progress in the console and the Scan tab.",
                     font=(_FUI, 9), bg=T["panel_bg"], fg=T["muted"],
                     justify="left", anchor="w", wraplength=480)
            _run_hint.pack(fill="x", pady=(6, 0))
            def _rrh(e, l=_run_hint): l.config(wraplength=max(200, e.width - 4))
            _run_hint.bind("<Configure>", _rrh)
            self._btn_next.config(text="Finalizar  ✓", bg=T["ok"],
                                  fg=T.get("button_fg", "#000000"))
        else:
            tk.Label(sec2,
                     text="Corrija los problemas anteriores, luego regrese a este paso para ejecutar el escaneo.",
                     font=(_FUI, 10), bg=T["panel_bg"], fg=T["accent"],
                     justify="left", anchor="w").pack(anchor="w")
            self._btn_next.config(text="Finish without scanning",
                                  bg=T.get("border_bg", T["border"]), fg=T["muted"])

    def _do_run_scan(self) -> None:
        try:
            if   hasattr(self._app, "_start_scan"): self._app._start_scan()
            elif hasattr(self._app, "_on_run"):      self._app._on_run()
            else:
                self._app._show_warn_popup(
                    "No se puede iniciar el escaneo",
                    "No scan entry-point found.\n\n"
                    "Close the wizard and start the scan from the ▶ Run Scan tab directly.")
                return
        except Exception as e:
            self._app._show_error_popup("Error de escaneo", f"No se pudo iniciar el escaneo:\n\n{e}")
            return
        self._popup.close()
        try: self._app._show_tab("scan")
        except Exception: pass
