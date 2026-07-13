from __future__ import annotations


import textwrap
import threading
import tkinter as tk
from tkinter import ttk

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

    Los pasos opcionales se omiten automáticamente si no elige la etapa correspondiente.
    ¡Comencemos — haga clic en "Siguiente" para empezar!
""")


class _WizardMixin:

    def open_wizard(self) -> None:
        existing = getattr(self, "_wizard_win", None)
        if existing and existing.winfo_exists():
            existing.lift(); existing.focus_force(); return
        _wiz_ref: list = []
        def _esc_forwarder():
            if _wiz_ref:
                _wiz_ref[0]._on_close()
        popup = self._create_popup("Asistente de configuración", 0.75, 0.75,
                                   on_escape=_esc_forwarder)
        self._wizard_win = popup._win
        wiz = _WizardWindow(self, popup)
        _wiz_ref.append(wiz)


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
        _STUBS = {"", "https://", "http://", "https:/", "http:/"}
        if url in _STUBS:
            return False, "Sin URL DAST — ingrese una URL completa (opcional — Omitir para saltar)."
        return True, f"DAST URL: {url}"

    def _wiz_check_api(self) -> tuple[bool, str]:
        try:
            spec = (getattr(self, "_api_spec_var", None) or tk.StringVar()).get().strip()
        except Exception:
            spec = ""
        if not spec:
            return False, "Sin especificación API — ingrese una ruta o URL (opcional — Omitir para saltar)."
        return True, f"Especificación API: {spec}"

    def _wiz_check_static_paths(self) -> tuple[bool, str]:
        lb = getattr(self, "_static_paths_lb", None)
        if lb is not None:
            paths = [p for p in lb.get(0, "end")
                     if p.strip() and not p.strip().startswith("(")]
            if paths:
                n = len(paths)
                return True, f"{n} ruta{'s' if n > 1 else ''} configurada{'s' if n > 1 else ''}"
        tv = getattr(self, "_target_var", None)
        if tv:
            val = tv.get().strip()
            if val:
                return True, f"Ruta configurada: {val}"
        return False, "Sin rutas — agregue al menos una carpeta o archivo."


    def _wiz_has_static_stages(self) -> bool:
        sv = getattr(self, "_scan_vars", {})
        return any(sv.get(k, tk.BooleanVar()).get() for k in ("sca", "code", "secrets"))

    def _wiz_has_dast_stage(self) -> bool:
        sv = getattr(self, "_scan_vars", {})
        v = sv.get("dast")
        return bool(v and v.get())

    def _wiz_has_api_stage(self) -> bool:
        sv = getattr(self, "_scan_vars", {})
        v = sv.get("api")
        return bool(v and v.get())


class _WizardWindow:
    

    _STEPS = [
        ("Bienvenido",      False, "_build_step_welcome"),
        ("Autenticación Snyk",    False, "_build_step_auth"),
        ("Perfil de app",  False, "_build_step_app"),
        ("Etapas de escaneo",  False, "_build_step_stages"),
        ("Rutas estáticas",    True,  "_build_step_static_paths"),
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


    def _build_chrome(self) -> None:
        hdr = self._app._popup_hdr(
            self._popup, "Asistente de configuración",
            icon="🛡", on_close=self._on_close,
        )
        self._hdr_step_lbl = tk.Label(
            hdr._row, text="", font=(_FUI, 9),
            bg=T["panel_bg"], fg=T["muted"],
        )
        self._hdr_step_lbl.pack(side="right", padx=(0, 10))

        self._drag_x = self._drag_y = 0
        for target in (hdr, hdr._row):
            target.bind("<ButtonPress-1>", self._drag_start)
            target.bind("<B1-Motion>",     self._drag_move)

        self._ribbon_frame = tk.Frame(self._popup, bg=T["panel_bg"])
        self._ribbon_frame.pack(fill="x")
        self._build_ribbon()

        self._content_outer = tk.Frame(self._popup, bg=T["bg"])
        self._content_outer.pack(fill="both", expand=True)

        tk.Frame(self._popup, bg=T["border_bg"], height=1).pack(fill="x")
        footer = tk.Frame(self._popup, bg=T["panel_bg"], height=56)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        self._status_var = tk.StringVar(value="")
        tk.Label(
            footer, textvariable=self._status_var,
            font=(_FUI, 9), bg=T["panel_bg"], fg=T["muted"], anchor="w",
        ).pack(side="left", padx=20, fill="x", expand=True)

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
        nx = event.x_root - self._drag_x
        ny = event.y_root - self._drag_y
        self._win.geometry(f"+{nx}+{ny}")
        shad = getattr(self._win, "_shadow_win", None)
        if shad and shad.winfo_exists():
            try:
                _SD = 10
                shad.geometry(
                    f"{self._win.winfo_width()}x{self._win.winfo_height()}"
                    f"+{nx + _SD}+{ny + _SD}"
                )
            except Exception:
                pass


    def _build_ribbon(self) -> None:
        for w in self._ribbon_frame.winfo_children():
            w.destroy()
        separator = tk.Frame(self._ribbon_frame, bg=T["border_bg"], height=1)
        separator.pack(side="bottom", fill="x")
        inner = tk.Frame(self._ribbon_frame, bg=T["panel_bg"])
        inner.pack(fill="x", padx=8, pady=(6, 4))
        total = len(self._STEPS)
        _label_refs = []
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
            available = inner.winfo_width()
            if available < 10:
                return
            cell_w = max(60, (available - (total - 1) * 18) // total - 4)
            for cell, lbl in _label_refs:
                lbl.config(wraplength=cell_w)

        inner.bind("<Configure>", _update_wraplengths)


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
        if self._STEPS[idx][2] == "_build_step_stages":
            self._auto_omit_from_stages()
        self._render_step(self._next_visible(idx + 1))

    def _do_prev(self) -> None:
        if self._step > 0:
            self._set_status("")
            self._render_step(self._prev_visible(self._step - 1))

    def _do_omit(self) -> None:
        idx = self._step
        if not self._STEPS[idx][1]: return
        all_empty = self._deselect_stages_for_step(idx)
        self._omitted.add(idx)
        self._set_status("")
        if all_empty:
            stages_idx = self._step_idx("_build_step_stages")
            self._render_step(stages_idx)
            self._set_status("Seleccione al menos una etapa de escaneo.", error=True)
            return
        self._render_step(self._next_visible(idx + 1))


    def _step_idx(self, builder_name: str) -> int:
        """Return the index in _STEPS whose builder matches builder_name."""
        for i, (_, _, b) in enumerate(self._STEPS):
            if b == builder_name:
                return i
        return 0

    def _next_visible(self, start: int) -> int:
        """First step index >= start that is NOT in _omitted (capped at last step)."""
        last = len(self._STEPS) - 1
        i = start
        while i < last and i in self._omitted:
            i += 1
        return i

    def _prev_visible(self, start: int) -> int:
        """First step index <= start that is NOT in _omitted (floored at 0)."""
        i = start
        while i > 0 and i in self._omitted:
            i -= 1
        return i

    def _auto_omit_from_stages(self) -> None:
        """Recalculate which optional steps to auto-omit based on current stage selection.
        Called every time the user leaves the stages step via Next."""
        static_idx = self._step_idx("_build_step_static_paths")
        dast_idx   = self._step_idx("_build_step_dast")
        api_idx    = self._step_idx("_build_step_api")

        if self._app._wiz_has_static_stages():
            self._omitted.discard(static_idx)
        else:
            self._omitted.add(static_idx)

        if self._app._wiz_has_dast_stage():
            self._omitted.discard(dast_idx)
        else:
            self._omitted.add(dast_idx)

        if self._app._wiz_has_api_stage():
            self._omitted.discard(api_idx)
        else:
            self._omitted.add(api_idx)

    def _deselect_stages_for_step(self, step_idx: int) -> bool:
        """Deselect the scan stages associated with the given optional step.
        Returns True if ALL stages are now disabled (nothing left to scan)."""
        builder  = self._STEPS[step_idx][2]
        sv       = getattr(self._app, "_scan_vars", {})
        keys_off: tuple[str, ...] = ()

        if builder == "_build_step_static_paths":
            keys_off = ("sca", "code", "secrets")
        elif builder == "_build_step_dast":
            keys_off = ("dast",)
        elif builder == "_build_step_api":
            keys_off = ("api",)

        for k in keys_off:
            v = sv.get(k)
            if v:
                v.set(False)
                apply_fn = getattr(self._app, "_stage_apply", {}).get(k)
                if apply_fn:
                    try: apply_fn(False)
                    except Exception: pass

        try: self._app._persist_scan_stages()
        except Exception: pass
        try: self._app._refresh_scan_btn()
        except Exception: pass

        return not any(v.get() for v in sv.values())

    def _on_finish(self) -> None:
        self._popup.close()
        try: self._app._log_line("[wizard] Asistente completado.")
        except Exception: pass
        sv = getattr(self._app, "_scan_vars", {})
        for k, v in sv.items():
            apply_fn = getattr(self._app, "_stage_apply", {}).get(k)
            if apply_fn:
                try: apply_fn(bool(v.get()))
                except Exception: pass
        try: self._app._refresh_stage_cards()
        except Exception: pass
        try: self._app._refresh_scan_btn()
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
        if name == "_build_step_welcome":        return True, ""
        if name == "_build_step_auth":           return self._app._wiz_check_auth()
        if name == "_build_step_app":            return self._app._wiz_check_app()
        if name == "_build_step_stages":         return self._app._wiz_check_stages()
        if name == "_build_step_static_paths":   return self._app._wiz_check_static_paths()
        if name == "_build_step_dast":           return self._app._wiz_check_dast()
        if name == "_build_step_api":            return self._app._wiz_check_api()
        return True, ""

    def _set_status(self, msg: str, *, error: bool = False) -> None:
        self._status_var.set(msg)
        footer = self._btn_next.master.master
        for w in footer.winfo_children():
            if isinstance(w, tk.Label):
                w.config(fg=T["err"] if error else T["muted"])
                break

    def _flash_next_invalid(self) -> None:
        self._btn_next.config(bg=T["err"])
        self._win.after(350, lambda: self._btn_next.config(bg=T["accent"]))

    def _maybe_prompt_probely(self) -> None:
        """When the user enables a cloud stage (DAST/API) that needs Snyk API &
        Web (Probely), surface the connect/paste-key popup — unless a validated
        key is already present. Mirrors the scan tab's behaviour so the wizard
        and the main UI feel identical."""
        app = self._app
        try:
            if getattr(app, "_probely_auth_status", "unauth") == "auth":
                return
            if hasattr(app, "_show_probely_key_popup"):
                app._show_probely_key_popup()
        except Exception:
            pass


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

    def _badge_canvas(self, parent, n: int) -> tk.Canvas:
        """Círculo naranja con número blanco (22×22 px) para guías numéricas."""
        c = tk.Canvas(parent, width=22, height=22,
                      bg=T["panel_bg"], highlightthickness=0)
        c.create_oval(1, 1, 21, 21, fill="#E67E22", outline="")
        c.create_text(11, 11, text=str(n), fill="#FFFFFF",
                      font=(_FUI, 8, "bold"))
        return c

    def _numbered_section(self, parent, text: str, n: int) -> tk.Frame:
        """Como _section() pero con badge numerado naranja en el header."""
        frame = tk.Frame(parent, bg=T["panel_bg"],
                         highlightbackground=T["border"], highlightthickness=1)
        frame.pack(fill="x", padx=16, pady=(0, 12))
        hdr_row = tk.Frame(frame, bg=T["panel_bg"])
        hdr_row.pack(fill="x", padx=12, pady=(10, 4))
        self._badge_canvas(hdr_row, n).pack(side="left", padx=(0, 6))
        tk.Label(hdr_row, text=text.upper(), font=(_FUI, 8, "bold"),
                 bg=T["panel_bg"], fg=T["accent"], anchor="w").pack(side="left")
        body = tk.Frame(frame, bg=T["panel_bg"])
        body.pack(fill="x", padx=12, pady=(0, 10))
        return body


    def _build_step_welcome(self, parent: tk.Frame) -> None:
        hero = tk.Frame(parent, bg=T["accent"])
        hero.pack(fill="x")
        tk.Label(hero, text="👋  Bienvenido a Snyk Scanner",
                 font=(_FUI, 16, "bold"), bg=T["accent"], fg="#FFFFFF").pack(
                     pady=(20, 4), padx=16, anchor="w")
        tk.Label(hero, text="Configuremos juntos su primer escaneo de seguridad.",
                 font=(_FUI, 11), bg=T["accent"], fg="#FFFFFF").pack(
                     pady=(0, 16), padx=16, anchor="w")

        for line in _WELCOME_TEXT.strip().splitlines():
            mono = line.startswith("  ")
            tk.Label(parent, text=line,
                     font=(_FMONO if mono else _FUI, 10),
                     bg=T["bg"],
                     fg=T["accent"] if mono else T["text"],
                     anchor="w", justify="left").pack(
                         fill="x", padx=16, pady=(2 if mono else 0, 0))


    def _build_step_auth(self, parent: tk.Frame) -> None:
        ok, msg = self._app._wiz_check_auth()
        launching = getattr(self, "_auth_launching", False)

        card = tk.Frame(parent, bg=T["panel_bg"],
                        highlightbackground=T["border"], highlightthickness=1)
        card.pack(fill="both", expand=True, padx=16, pady=12)

        _img_ref = [None]
        left = tk.Frame(card, bg=T["panel_bg"])
        left.pack(side="left", padx=(12, 8), pady=16, anchor="n")
        try:
            img_path = AUTH_LOGO_PATH
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
        self._render_step(self._step)

        _prev_close = getattr(self._app, "_login_popup_close", None)

        def _on_auth_complete():
            self._auth_launching = False
            if callable(_prev_close):
                try: _prev_close()
                except Exception: pass
            if self._win.winfo_exists() and self._step == 1:
                self._render_step(self._step)

        self._app._login_popup_close = _on_auth_complete

        def _run():
            try:
                import sys as _sys, time as _time, queue as _queue
                _main_mod = (_sys.modules.get("Snyk_Scanner_GUI")
                             or _sys.modules.get("__main__"))
                _fn = getattr(_main_mod, "start_snyk_auth", None)
                if _fn is None:
                    import webbrowser as _wb
                    _wb.open("https://app.snyk.io/login?redirectUri=/")
                    return
                proc = _fn(self._app._emit_log)
                if proc is not None and hasattr(self._app, "_auth_proc"):
                    _timeout = getattr(_main_mod, "AUTH_POLL_TIMEOUT", 300)
                    self._app._auth_proc     = proc
                    self._app._auth_deadline = _time.time() + _timeout
                    self._app._auth_lines    = _queue.Queue()
                    def _reader(p=proc, q=self._app._auth_lines):
                        try:
                            if p.stdout:
                                for line in iter(p.stdout.readline, ""):
                                    if not line:
                                        break
                                    q.put(line)
                        except Exception:
                            pass
                    import threading as _th
                    _th.Thread(target=_reader, daemon=True).start()
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


    def _build_step_app(self, parent: tk.Frame) -> None:
        ok, msg = self._app._wiz_check_app()
        self._body_text(parent,
            "Un Perfil de App agrupa su objetivo, configuración e historial de vulnerabilidades "
            "para rastrear resultados en el tiempo y compararlos entre escaneos.")

        sec2 = self._section(parent, "Seleccionar o crear perfil")
        label_btn = "📋  Seleccionar / editar aplicación" if ok else "📋  Seleccionar o crear aplicación"
        self._inline_btn(sec2, label_btn, self._wiz_open_app_editor)
        _hint = tk.Label(sec2,
                 text="Elige una app existente o crea una nueva — se cargará automáticamente.",
                 font=(_FUI, 9), bg=T["panel_bg"], fg=T["muted"],
                 justify="left", anchor="w", wraplength=480)
        _hint.pack(fill="x", pady=(4, 0))
        def _rh(e, l=_hint): l.config(wraplength=max(200, e.width - 4))
        _hint.bind("<Configure>", _rh)

        sec_active = self._section(parent, "Perfil de aplicación activo")
        self._status_row(sec_active, ok, msg)
        if ok:
            app = getattr(self._app, "_active_app", {}) or {}
            for lbl, val in [
                ("Nombre",                app.get("name",        "—")),
                ("Tipo",                  app.get("app_type",    "—")),
                ("Criticidad de negocio", app.get("criticality", "—")),
                ("Ruta objetivo",         app.get("target_path", "—") or "—"),
                ("DAST URL",              app.get("dast_url",    "—") or "—"),
            ]:
                row = tk.Frame(sec_active, bg=T["panel_bg"])
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

    def _wiz_open_app_editor(self) -> None:
        """Abre AppProfileEditor centrado sobre la ventana principal.
        Al guardar, auto-carga la app como activa y re-renderiza el paso."""
        try:
            from app_inventory import AppProfileEditor
            store = getattr(self._app, "_inv_store", None)
            if store is None:
                self._set_status("⚠  Inventario no disponible.", error=True)
                return
            ed = AppProfileEditor(self._app, store)
            self._win.wait_window(ed)
            if ed.result:
                try:
                    self._app._load_app_profile(ed.result, silent=True)
                except Exception:
                    pass
                self._render_step(self._step)
        except Exception as exc:
            self._set_status(f"⚠  Error al abrir editor: {exc}", error=True)


    def _build_step_stages(self, parent: tk.Frame) -> None:
        self._body_text(parent,
            "Elija qué etapas de análisis ejecutar. Cada etapa apunta a un tipo diferente "
            "layer of your application.  SCA and Code Analysis are recommended for all apps.")

        scan_vars: dict[str, tk.BooleanVar] = getattr(self._app, "_scan_vars", {})
        if not scan_vars:
            sec = self._section(parent, "Selección de etapas")
            tk.Label(sec, text="⚠  scan_vars no encontrado — verifique el cableado de la interfaz.",
                     font=(_FUI, 9), bg=T["panel_bg"], fg=T["err"]).pack(anchor="w")
            return

        _STAGE_META = {
            "sca":     ("📦  SCA",               "Vulnerabilidades en dependencias de código abierto"),
            "code":    ("🔍  Análisis de código", "Análisis de código estático (Snyk Code)"),
            "secrets": ("🔑  Secrets",            "Credenciales y tokens expuestos en el código"),
            "iac":     ("🏗  IaC",                "Configuraciones incorrectas de Infraestructura como Código"),
            "dast":    ("🌐  DAST",               "Análisis dinámico — requiere una URL activa"),
            "api":     ("🔌  Seguridad de API",   "Escaneo a nivel de API — requiere una especificación"),
            "image":   ("🐳  Contenedor",          "Escaneo de vulnerabilidades en imágenes Docker"),
        }
        _ORDER = ["sca", "secrets", "code", "dast", "api", "iac", "image"]
        _ordered_keys = [k for k in _ORDER if k in scan_vars] + \
                        [k for k in scan_vars if k not in _ORDER]

        _select_all_var = tk.BooleanVar(value=all(v.get() for v in scan_vars.values()))

        def _on_select_all():
            state = _select_all_var.get()
            for k, v in scan_vars.items():
                v.set(state)
                apply_fn = getattr(self._app, "_stage_apply", {}).get(k)
                if apply_fn:
                    try: apply_fn(state)
                    except Exception: pass
            try: self._app._persist_scan_stages()
            except Exception: pass
            try: self._app._refresh_scan_btn()
            except Exception: pass
            # 'Select all' can enable DAST/API — prompt for Probely if so.
            if state and any(k in scan_vars for k in ("dast", "api")):
                self._maybe_prompt_probely()

        def _sync_select_all_state():
            all_on  = all(v.get() for v in scan_vars.values())
            all_off = not any(v.get() for v in scan_vars.values())
            if all_on:   _select_all_var.set(True)
            elif all_off: _select_all_var.set(False)

        frame = tk.Frame(parent, bg=T["panel_bg"],
                         highlightbackground=T["border"], highlightthickness=1)
        frame.pack(fill="x", padx=16, pady=(0, 12))

        hdr_row = tk.Frame(frame, bg=T["panel_bg"])
        hdr_row.pack(fill="x", padx=12, pady=(10, 4))
        ttk.Checkbutton(
            hdr_row, variable=_select_all_var, command=_on_select_all,
        ).pack(side="left")
        tk.Label(hdr_row, text="SELECCIÓN DE ETAPAS", font=(_FUI, 8, "bold"),
                 bg=T["panel_bg"], fg=T["accent"], anchor="w").pack(side="left", padx=(4, 0))

        sec = tk.Frame(frame, bg=T["panel_bg"])
        sec.pack(fill="x", padx=12, pady=(0, 10))

        tk.Frame(sec, bg=T["border_bg"], height=1).pack(fill="x", pady=(0, 4))

        for key in _ordered_keys:
            var = scan_vars[key]
            label, desc = _STAGE_META.get(key, (key.upper(), ""))
            row = tk.Frame(sec, bg=T["panel_bg"])
            row.pack(fill="x", pady=3)

            def _make_stage_cmd(v=var, k=key):
                def _cmd():
                    apply_fn = getattr(self._app, "_stage_apply", {}).get(k)
                    if apply_fn:
                        try: apply_fn(v.get())
                        except Exception: pass
                    try: self._app._persist_scan_stages()
                    except Exception: pass
                    try: self._app._refresh_scan_btn()
                    except Exception: pass
                    _sync_select_all_state()
                    # Selecting a cloud stage (DAST/API) needs a Probely key.
                    # Prompt for it the same way the scan tab does.
                    if k in ("dast", "api") and v.get():
                        self._maybe_prompt_probely()
                return _cmd

            ttk.Checkbutton(
                row, variable=var,
                command=_make_stage_cmd(),
            ).pack(side="left")
            col = tk.Frame(row, bg=T["panel_bg"])
            col.pack(side="left", padx=6)
            tk.Label(col, text=label, font=(_FUI, 10, "bold"),
                     bg=T["panel_bg"], fg=T["text"]).pack(anchor="w")
            if desc:
                tk.Label(col, text=desc, font=(_FUI, 9),
                         bg=T["panel_bg"], fg=T["muted"]).pack(anchor="w")


    def _build_step_static_paths(self, parent: tk.Frame) -> None:
        self._body_text(parent,
            "Agregue las carpetas o archivos de código que serán analizados estáticamente.")

        sec = self._section(parent, "Rutas de análisis estático")

        lb_frame = tk.Frame(sec, bg=T["panel_bg"])
        lb_frame.pack(fill="x", pady=(0, 6))
        lb = tk.Listbox(
            lb_frame, height=5, font=(_FMONO, 9),
            bg=T["surface2"], fg=T["text"], selectmode="extended",
            highlightthickness=1, highlightbackground=T["border"],
            activestyle="none", selectbackground=T["accent"],
            selectforeground=T.get("button_fg", "#ffffff"), relief="flat",
        )
        _sb = ttk.Scrollbar(lb_frame, orient="vertical", command=lb.yview)
        lb.configure(yscrollcommand=_sb.set)
        lb.pack(side="left", fill="both", expand=True)
        _sb.pack(side="right", fill="y")

        _PLACEHOLDER = "  (vacío — use los botones para agregar rutas)"

        def _real_paths():
            return [p for p in lb.get(0, "end")
                    if p.strip() and not p.strip().startswith("(")]

        def _show_placeholder():
            lb.delete(0, "end")
            lb.insert("end", _PLACEHOLDER)
            lb.itemconfig(0, fg=T["muted"])

        def _clear_placeholder():
            items = lb.get(0, "end")
            if len(items) == 1 and items[0].strip().startswith("("):
                lb.delete(0, "end")

        app_lb = getattr(self._app, "_static_paths_lb", None)
        if app_lb is not None:
            for p in app_lb.get(0, "end"):
                if p.strip() and not p.strip().startswith("("):
                    lb.insert("end", p)
        if lb.size() == 0:
            tv = getattr(self._app, "_target_var", None)
            tvval = tv.get().strip() if tv else ""
            if tvval:
                lb.insert("end", tvval)
        if lb.size() == 0:
            _show_placeholder()

        def _sync_to_app():
            """Push wizard listbox contents back into the app's _static_paths_lb."""
            app_lb2 = getattr(self._app, "_static_paths_lb", None)
            if app_lb2 is not None:
                app_lb2.delete(0, "end")
                for p in _real_paths():
                    app_lb2.insert("end", p)
            try: self._app._persist_static_paths()
            except Exception: pass
            tv = getattr(self._app, "_target_var", None)
            rp = _real_paths()
            if rp and tv:
                tv.set(rp[-1])

        def _add_folder():
            from tkinter import filedialog
            tv = getattr(self._app, "_target_var", None)
            initial = tv.get().strip() if tv else ""
            with _popup_dialog_guard(self._win):
                d = filedialog.askdirectory(
                    title="Agregar carpeta al escaneo",
                    initialdir=initial or ".",
                    parent=self._win,
                )
            if d:
                _clear_placeholder()
                if d not in _real_paths():
                    lb.insert("end", d)
                _sync_to_app()

        def _add_files():
            from tkinter import filedialog
            tv = getattr(self._app, "_target_var", None)
            initial = tv.get().strip() if tv else ""
            with _popup_dialog_guard(self._win):
                files = filedialog.askopenfilenames(
                    title="Agregar archivos o .csproj al escaneo",
                    initialdir=initial or ".",
                    filetypes=[
                        ("Todos los compatibles",
                         "*.csproj *.sln *.json *.py *.js *.ts *.cs *.java *.go *.rb *.php"),
                        ("Proyectos Visual Studio", "*.csproj *.sln"),
                        ("Manifiestos de dependencias", "*.json *.xml *.lock *.toml *.gradle"),
                        ("Código fuente", "*.py *.js *.ts *.cs *.java *.go *.rb *.php *.cpp *.c *.h"),
                        ("Todos los archivos", "*.*"),
                    ],
                    parent=self._win,
                )
            if files:
                _clear_placeholder()
                existing = _real_paths()
                for f in files:
                    if f not in existing:
                        lb.insert("end", f)
                        existing.append(f)
                _sync_to_app()

        def _remove_sel():
            sel = list(lb.curselection())
            for i in reversed(sel):
                lb.delete(i)
            if not _real_paths():
                _show_placeholder()
            _sync_to_app()

        btn_row = tk.Frame(sec, bg=T["panel_bg"])
        btn_row.pack(fill="x", pady=(0, 6))
        self._app._btn(btn_row, "📂  Carpeta…",   _add_folder, "outline").pack(side="left", padx=(0, 4))
        self._app._btn(btn_row, "📄  Archivo(s)…", _add_files,  "outline").pack(side="left", padx=(0, 4))
        self._app._btn(btn_row, "−  Eliminar",     _remove_sel, "outline").pack(side="left")


    def _build_step_dast(self, parent: tk.Frame) -> None:
        sec_url = self._numbered_section(parent, "URL del objetivo", 1)
        dast_url_var = getattr(self._app, "_dast_url_var", None)
        if dast_url_var is None:
            tk.Label(sec_url, text="⚠  _dast_url_var no encontrado.",
                     font=(_FUI, 9), bg=T["panel_bg"], fg=T["err"]).pack(anchor="w")
        else:
            self._field_row(sec_url, "URL de la aplicación", dast_url_var)

        sec_prof = self._numbered_section(parent, "Perfil de escaneo", 2)
        dast_profile_var = getattr(self._app, "_dast_profile_var", None)
        if dast_profile_var is None:
            tk.Label(sec_prof, text="⚠  _dast_profile_var no encontrado.",
                     font=(_FUI, 9), bg=T["panel_bg"], fg=T["err"]).pack(anchor="w")
        else:
            from tkinter import ttk as _ttk
            prof_row = tk.Frame(sec_prof, bg=T["panel_bg"])
            prof_row.pack(fill="x", pady=(2, 4))
            tk.Label(prof_row, text="Perfil", font=(_FUI, 9),
                     bg=T["panel_bg"], fg=T["muted"], width=16, anchor="w").pack(side="left")
            _ttk.Combobox(prof_row, textvariable=dast_profile_var,
                          values=["(predeterminado)", "lightning", "safe", "normal", "full"],
                          state="readonly", width=14).pack(side="left")
            _hint_prof = tk.Label(sec_prof,
                     text="Perfil de escaneo de Probely. Lightning — rápido, mínimos payloads "
                          "(válido para dominios sin verificar).  Safe — solo métodos seguros "
                          "(GET/HEAD), ideal para producción.  Normal — equilibrado.  "
                          "Full — máxima cobertura de payloads, tarda más. (predeterminado) usa "
                          "el perfil configurado en el target.",
                     font=(_FUI, 9), bg=T["panel_bg"], fg=T["muted"],
                     justify="left", anchor="w", wraplength=480)
            _hint_prof.pack(fill="x", pady=(2, 0))
            def _rp(e, l=_hint_prof): l.config(wraplength=max(200, e.width - 4))
            _hint_prof.bind("<Configure>", _rp)

        # ── Probely connection (per-user API key) ──────────────────────────────
        # The cloud DAST/API scan uses Snyk API & Web (Probely), which needs the
        # user's OWN API key — separate from the Snyk SSO login. Show its status
        # and let them paste/validate it right here.
        sec_prob = self._numbered_section(parent, "Conexión con Probely (Snyk API & Web)", 3)
        prob_status = getattr(self._app, "_probely_auth_status", "unauth")
        prob_ok = (prob_status == "auth")
        prob_has = self._app._probely_configured() if hasattr(self._app, "_probely_configured") else False
        if prob_ok:
            _pmsg = "Probely conectado ✓ — clave de API validada."
        elif prob_has:
            _pmsg = "Clave de Probely guardada pero SIN validar — pulse «Conectar Probely» para validarla."
        else:
            _pmsg = ("Probely NO conectado — el escaneo en la nube necesita TU clave de API "
                     "(distinta del login de Snyk).")
        self._status_row(sec_prob, prob_ok, _pmsg)
        _prob_btn_row = tk.Frame(sec_prob, bg=T["panel_bg"])
        _prob_btn_row.pack(fill="x", pady=(8, 0))
        self._app._btn(_prob_btn_row, "🌐  Conectar Probely (pegar clave)…",
                       self._app._show_probely_key_popup, "accent").pack(side="left")
        self._body_text(parent,
            "Solicita tu clave de API al equipo de Ciberseguridad "
            "(slunam@bancobase.com) y pégala con el botón de arriba.")

        # ── Pool de targets (orquestador) ─────────────────────────────────────
        sec_pool = self._numbered_section(parent, "Pool de targets (orquestador)", 4)
        from tkinter import ttk as _ttk_pool
        orch_var = getattr(self._app, "_dast_orch_var", None)
        if orch_var is not None:
            _ttk_pool.Checkbutton(sec_pool, text="Orquestar el pool automáticamente al escanear",
                                  variable=orch_var).pack(anchor="w", pady=(2, 4))
        prow = tk.Frame(sec_pool, bg=T["panel_bg"]); prow.pack(fill="x", pady=(0, 2))
        cool = getattr(self._app, "_dast_cooldown_var", None)
        if cool is not None:
            self._app._spin(prow, "Enfriamiento por slot (min)", cool, 0, 1440, width=6)
        self._body_text(parent,
            "Los escaneos comparten un pool limitado de targets. El orquestador "
            "administra la fila y te asigna tu lugar automáticamente al escanear.")

        sec_macro = self._section(parent, "Login (opcional)")
        _state = {"login": bool(
            getattr(self._app, "_dast_cred_vars", {}).get("selenium_macro", tk.StringVar()).get().strip()
            or getattr(self._app, "_dast_cred_vars", {}).get("selenium_login_url", tk.StringVar()).get().strip()
        )}
        _login_status_var = tk.StringVar(value="✔  Grabado" if _state["login"] else "⬜  No grabado")

        _btn_grid = tk.Frame(sec_macro, bg=T["panel_bg"]); _btn_grid.pack(fill="x")
        _btn_grid.columnconfigure(2, weight=1)

        def _refresh_login_label():
            _login_status_var.set("✔  Grabado" if _state["login"] else "⬜  No grabado")
            if hasattr(_login_lbl, "config"):
                _login_lbl.config(fg=T["ok"] if _state["login"] else T["muted"])

        def _do_record_login():
            try:
                if self._app._dast_record_macro():
                    _state["login"] = True
                    _refresh_login_label()
            except Exception as exc:
                self._set_status(f"⚠  Error al grabar login: {exc}", error=True)

        self._badge_canvas(_btn_grid, 4).grid(row=0, column=0, sticky="w",
                                               padx=(0, 6), pady=(0, 4))
        _login_btn = self._app._btn(_btn_grid, "⏺  Grabar login → secuencia",
                                    _do_record_login, "accent")
        _login_btn.grid(row=0, column=1, sticky="ew", pady=(0, 4))
        _login_lbl = tk.Label(_btn_grid, textvariable=_login_status_var,
                              font=(_FUI, 10, "bold"), bg=T["panel_bg"],
                              fg=T["ok"] if _state["login"] else T["muted"])
        _login_lbl.grid(row=0, column=2, sticky="w", padx=(10, 0), pady=(0, 4))

        self._body_text(parent,
            "El login grabado se sube a Probely como secuencia de inicio de sesión. Para un formulario "
            "simple, elija el tipo de autenticación «form» en la pestaña DAST (puede fijar un patrón de "
            "verificación de login). Probely vuelve a iniciar sesión solo si la sesión se cae durante el "
            "escaneo — no hace falta grabar ni probar el logout.")


    def _build_step_api(self, parent: tk.Frame) -> None:
        from tkinter import ttk as _ttk

        sec = self._numbered_section(parent, "Ruta o URL de la especificación API", 1)
        api_spec_var = getattr(self._app, "_api_spec_var", None)
        if api_spec_var is None:
            tk.Label(sec, text="⚠  _api_spec_var no encontrado.",
                     font=(_FUI, 9), bg=T["panel_bg"], fg=T["err"]).pack(anchor="w")
        else:
            spec_row = tk.Frame(sec, bg=T["panel_bg"])
            spec_row.pack(fill="x", pady=(4, 0))
            def _browse_spec():
                from tkinter import filedialog
                with _popup_dialog_guard(self._win):
                    p = filedialog.askopenfilename(
                        title="Seleccionar especificación API",
                        filetypes=[("OpenAPI / Swagger", "*.yaml *.yml *.json"),
                                    ("Todos los archivos", "*.*")],
                        parent=self._win)
                if p: api_spec_var.set(p)
            self._app._btn(spec_row, "📂  Explorar", _browse_spec, "outline").pack(
                side="left", padx=(0, 8))
            tk.Label(spec_row, text="Especificación", font=(_FUI, 9),
                     bg=T["panel_bg"], fg=T["muted"]).pack(side="left", padx=(0, 4))
            _ttk.Entry(spec_row, textvariable=api_spec_var).pack(
                side="left", fill="x", expand=True)

        api_base_var = getattr(self._app, "_api_base_var", None)
        if api_base_var is not None:
            self._field_row(sec, "URL base del API objetivo (opcional)", api_base_var)
        self._body_text(parent,
            "El escaneo de API se registra como un target de tipo «API» en Probely y ocupa uno "
            "de los 5 slots compartidos con DAST. Si activas DAST y API juntos, se usan dos slots "
            "(uno Web, uno API). El orquestador (paso «Pool de targets») los gestiona igual para ambos.")

        sec_auth = self._section(parent, "Autenticación de la API")
        api_auth_var  = getattr(self._app, "_api_auth_var",  None)
        api_cred_vars = getattr(self._app, "_api_cred_vars", {})

        _AUTH_FIELDS = {
            "none":   [],
            "basic":  [("username", "Usuario",        False),
                       ("password", "Contraseña",      True)],
            "bearer": [("token",    "Token Bearer",    True)],
            "cookie": [("cookie",   "Valor de Cookie", False)],
            "header": [("header_name",  "Nombre de cabecera", False),
                       ("header_value", "Valor de cabecera",  True)],
        }

        if api_auth_var is None:
            tk.Label(sec_auth, text="⚠  _api_auth_var no encontrado.",
                     font=(_FUI, 9), bg=T["panel_bg"], fg=T["err"]).pack(anchor="w")
        else:
            auth_row = tk.Frame(sec_auth, bg=T["panel_bg"])
            auth_row.pack(fill="x", pady=(0, 8))
            self._badge_canvas(auth_row, 2).pack(side="left", padx=(0, 6))
            tk.Label(auth_row, text="Tipo de auth", font=(_FUI, 9),
                     bg=T["panel_bg"], fg=T["muted"], width=16, anchor="w").pack(side="left")
            _ttk.Combobox(auth_row, textvariable=api_auth_var,
                          values=["none", "basic", "bearer", "cookie", "header"],
                          state="readonly", width=12).pack(side="left")

            _cred_container = tk.Frame(sec_auth, bg=T["panel_bg"])
            _cred_container.pack(fill="x")

            def _rebuild_cred_fields(*_):
                for w in _cred_container.winfo_children():
                    w.destroy()
                kind = api_auth_var.get()
                for badge_n, (key, label, secret) in enumerate(
                        _AUTH_FIELDS.get(kind, []), start=3):
                    var = api_cred_vars.get(key)
                    if var is None:
                        continue
                    row = tk.Frame(_cred_container, bg=T["panel_bg"])
                    row.pack(fill="x", pady=(2, 0))
                    self._badge_canvas(row, badge_n).pack(side="left", padx=(0, 6))
                    tk.Label(row, text=label, font=(_FUI, 9),
                             bg=T["panel_bg"], fg=T["muted"],
                             width=16, anchor="w").pack(side="left")
                    _ttk.Entry(row, textvariable=var,
                               show="*" if secret else "").pack(
                                   side="left", fill="x", expand=True)

            api_auth_var.trace_add("write", _rebuild_cred_fields)
            _rebuild_cred_fields()


    def _build_step_run(self, parent: tk.Frame) -> None:
        auth_ok,   auth_msg   = self._app._wiz_check_auth()
        app_ok,    app_msg    = self._app._wiz_check_app()
        stages_ok, stages_msg = self._app._wiz_check_stages()
        static_ok, static_msg = self._app._wiz_check_static_paths()
        dast_ok,   dast_msg   = self._app._wiz_check_dast()
        api_ok,    api_msg    = self._app._wiz_check_api()

        static_idx = self._step_idx("_build_step_static_paths")
        dast_idx   = self._step_idx("_build_step_dast")
        api_idx    = self._step_idx("_build_step_api")
        static_omitted = static_idx in self._omitted
        dast_omitted   = dast_idx   in self._omitted
        api_omitted    = api_idx    in self._omitted

        sec = self._section(parent, "Resumen de configuración")
        self._status_row(sec, auth_ok,   f"Auth:          {auth_msg}")
        self._status_row(sec, app_ok,    f"App:           {app_msg}")
        self._status_row(sec, stages_ok, f"Etapas:        {stages_msg}")
        self._status_row(
            sec,
            True if static_omitted else static_ok,
            "Rutas estáticas:  omitido" if static_omitted else f"Rutas estáticas:  {static_msg}",
        )
        self._status_row(
            sec,
            True if dast_omitted else dast_ok,
            "DAST:          omitido" if dast_omitted else f"DAST:          {dast_msg}",
        )
        self._status_row(
            sec,
            True if api_omitted else api_ok,
            "API:           omitido" if api_omitted  else f"API:           {api_msg}",
        )

        # Probely connection status — only relevant when a cloud stage is on.
        sv = getattr(self._app, "_scan_vars", {})
        cloud_selected = any(bool(sv.get(k) and sv[k].get()) for k in ("dast", "api"))
        if cloud_selected:
            prob_ok = (getattr(self._app, "_probely_auth_status", "unauth") == "auth")
            prob_has = (self._app._probely_configured()
                        if hasattr(self._app, "_probely_configured") else False)
            if prob_ok:
                prob_msg = "Probely:       conectado ✓"
            elif prob_has:
                prob_msg = "Probely:       clave sin validar — pulse 🌐 para validar"
            else:
                prob_msg = "Probely:       NO conectado — requerido para DAST / API (icono 🌐)"
            self._status_row(sec, prob_ok, prob_msg)

        ready = auth_ok and app_ok and stages_ok
        sec2 = self._section(parent, "Iniciar")
        if ready:
            self._inline_btn(sec2, "🚀  Ejecutar escaneo ahora", self._do_run_scan)
            self._btn_next.config(text="Finalizar  ✓", bg=T["ok"],
                                  fg=T.get("button_fg", "#000000"))
        else:
            self._body_text(parent,
                "⚠  Corrija los pasos requeridos antes de ejecutar el escaneo.", fg=T["err"])
            self._btn_next.config(text="Finalizar sin escanear",
                                  bg=T.get("border_bg", T["border"]), fg=T["muted"])

    def _do_run_scan(self) -> None:
        sv = getattr(self._app, "_scan_vars", {})
        for k, v in sv.items():
            apply_fn = getattr(self._app, "_stage_apply", {}).get(k)
            if apply_fn:
                try: apply_fn(bool(v.get()))
                except Exception: pass
        try: self._app._refresh_stage_cards()
        except Exception: pass
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