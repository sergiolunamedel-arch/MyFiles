from __future__ import annotations

"""ScannerApp mixin: the (Scan) tab -- prerequisites checklist, Snyk SSO login flow, and the unified pipeline orchestrator (_do_scan) that runs whichever of SCA/SAST/DAST/API/Secrets are selected, in parallel where independent.

Lives in its own file purely for editor sanity -- this is still
logically part of Snyk_Scanner_GUI.py: it shares that module's globals
(T, fonts, helper functions, the runtime-injected engine calls) via
_wire_mixin_globals(), the same trick _load_runtime() already uses to
pull static_scanner/dast_api/report_engine symbols into this module.
Do not import this file standalone or instantiate this class on its
own -- it has no meaning outside being mixed into ScannerApp."""

class _ScanTabMixin:
    def _build_tab_scan(self, parent):
        self._section_header(parent, '▶  Scan Dashboard')
        pad = self._scrollable(parent)

        app_banner = tk.Frame(pad, bg=T["surface2"], highlightthickness=1, highlightbackground=T["border"])
        app_banner.pack(fill="x", pady=(0, 8))
        banner_inner = tk.Frame(app_banner, bg=T["surface2"], padx=14, pady=7); banner_inner.pack(fill="x")
        tk.Label(banner_inner, text="📦  Active App:", font=(_FUI, 10, "bold"), bg=T["surface2"], fg=T["muted"]).pack(side="left")
        self._active_app_lbl = tk.Label(banner_inner, text="None — go to 📦 Apps tab to load a profile",
                                        font=(_FUI, 10), bg=T["surface2"], fg=T["muted"])
        self._active_app_lbl.pack(side="left", padx=(8, 0))
        tk.Button(banner_inner, text="📦 Switch App", command=lambda: self._show_tab("apps"),
                  bg=T["surface2"], fg=T["accent"], font=(_FUI, 10), relief="flat", padx=8, cursor="hand2",
                  activebackground=T["card_hover"], activeforeground=T["accent_hi"]).pack(side="right")

        cards_row = tk.Frame(pad, bg=T["bg"]); cards_row.pack(fill="x", pady=(0, 0))

        pipe_outer = tk.Frame(cards_row, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        pipe_outer.pack(side="left", fill="both", expand=True, padx=(0, 6))

        # ── Pipeline header: Canvas que actúa como barra de progreso general ──
        # Usamos create_text (no create_window+Label) para que el texto sea
        # transparente sobre el canvas — los Labels de tkinter siempre pintan
        # su propio fondo opaco y crean el mismatch de color que se ve en la captura.
        _PH_H = 32
        _PH_FG = T["button_fg"]   # blanco/negro según tema
        _PH_FONT_BOLD = (_FUI, 10, "bold")
        _PH_FONT_SM   = (_FUI, 9)

        # Color del fill de progreso: versión más oscura del accent.
        def _progress_fill_color():
            base = T["accent"]          # e.g. "#F5A800"
            try:
                r = int(base[1:3], 16); g = int(base[3:5], 16); b = int(base[5:7], 16)
                r2 = max(0, r - 60); g2 = max(0, g - 40); b2 = max(0, b)
                return f"#{r2:02x}{g2:02x}{b2:02x}"
            except Exception:
                return "#b85c00"

        self._pipe_hdr_canvas = tk.Canvas(pipe_outer, height=_PH_H, highlightthickness=0,
                                          bd=0, bg=T["accent"])
        self._pipe_hdr_canvas.pack(fill="x")
        # 1. Fondo sólido accent
        self._pipe_hdr_canvas.create_rectangle(0, 0, 4000, _PH_H, fill=T["accent"], outline="",
                                               tags="bg_rect")
        # 2. Fill de progreso (tono más oscuro del accent)
        self._pipe_hdr_canvas.create_rectangle(0, 0, 0, _PH_H,
                                               fill=_progress_fill_color(), outline="",
                                               tags="prog_rect")
        # 3. Texto "PIPELINE" — nativo del canvas, sin caja opaca propia
        self._pipe_hdr_canvas.create_text(14, _PH_H // 2, anchor="w",
                                          text="PIPELINE", fill=_PH_FG,
                                          font=_PH_FONT_BOLD, tags="txt_title")
        # 4. Texto de progreso — lado derecho
        self._pipe_hdr_canvas.create_text(4000 - 14, _PH_H // 2, anchor="e",
                                          text="— idle", fill=_PH_FG,
                                          font=_PH_FONT_SM, tags="txt_prog")

        self._pipe_progress_pct = 0.0
        self._pipe_stage_states: dict[str, str] = {}

        def _ph_resize(evt):
            w = max(evt.width, 1)
            cnv = self._pipe_hdr_canvas
            cnv.configure(bg=T["accent"])
            cnv.itemconfigure("bg_rect", fill=T["accent"])
            cnv.coords("bg_rect", 0, 0, w, _PH_H)
            cnv.itemconfigure("txt_title", fill=T["button_fg"])
            cnv.itemconfigure("txt_prog",  fill=T["button_fg"])
            cnv.coords("txt_prog", w - 14, _PH_H // 2)
            pct = getattr(self, "_pipe_progress_pct", 0.0)
            cnv.coords("prog_rect", 0, 0, int(w * pct), _PH_H)
            cnv.itemconfigure("prog_rect", fill=_progress_fill_color())

        self._pipe_hdr_canvas.bind("<Configure>", _ph_resize)
        self._pipe_hdr_set_prog_text = lambda txt: (
            self._pipe_hdr_canvas.itemconfigure("txt_prog", text=txt)
        )
        self._pipe_hdr_get_fill_color = _progress_fill_color
        pipe = tk.Frame(pipe_outer, bg=T["panel_bg"], padx=10, pady=10); pipe.pack(fill="both", expand=True)
        pipe.columnconfigure(0, weight=1, uniform="sc"); pipe.columnconfigure(1, weight=1, uniform="sc")

        _STAGES = [
            ("sca",     "1", "Open-source (SCA)",  "CVE scan on\ndependency manifests"),
            ("code",    "2", "Static code (SAST)", "Security issues\nin source files"),
            ("secrets", "3", "Secret Scanning",    "Hard-coded keys\n& tokens (CWE-798)"),
            ("dast",    "4", "Dynamic (DAST)",     "Live URL crawl\n& probe injection"),
            ("api",     "5", "API Security",       "OpenAPI/Swagger\nendpoint probing"),
        ]

        def _make_stage_card(key, num, name, desc, grid_row, col):
            cell = tk.Frame(pipe, bg=T["surface2"], highlightthickness=1, highlightbackground=T["border"], cursor="hand2")
            cell.grid(row=grid_row, column=col, padx=4, pady=4, sticky="nsew")
            top = tk.Frame(cell, bg=T["surface2"], padx=8, pady=6); top.pack(fill="x")
            badge = tk.Label(top, text=num, font=(_FUI, 12, "bold"), bg=T["accent"], fg=T["button_fg"], padx=6)
            badge.pack(side="left")
            name_lbl = tk.Label(top, text=name, font=(_FUI, 10, "bold"), bg=T["surface2"], fg=T["text"]); name_lbl.pack(side="left", padx=8)
            pill = tk.Label(top, text="● IDLE", font=(_FUI, 8), bg=T["pill_idle_bg"], fg=T["pill_idle_fg"], padx=6, pady=2)
            pill.pack(side="right")
            desc_lbl = tk.Label(cell, text=desc, font=(_FUI, 8), bg=T["surface2"], fg=T["muted"], anchor="w", justify="left", padx=8)
            desc_lbl.pack(fill="x", pady=(0, 4))

            # ── Barra de progreso por card ──────────────────────────────────
            _BAR_H = 4
            bar_canvas = tk.Canvas(cell, height=_BAR_H, highlightthickness=0, bd=0,
                                   bg=T["surface2"])
            bar_canvas.pack(fill="x", padx=6, pady=(0, 6))
            bar_canvas.create_rectangle(0, 0, 4000, _BAR_H, fill=T["border"], outline="",
                                        tags="bar_bg")
            bar_canvas.create_rectangle(0, 0, 0, _BAR_H, fill=T["accent"], outline="",
                                        tags="bar_fill")

            def _bar_resize(evt, bc=bar_canvas):
                w = max(evt.width, 1)
                bc.coords("bar_bg", 0, 0, w, _BAR_H)
                pct = getattr(bc, "_pct", 0.0)
                clr = getattr(bc, "_clr", T["accent"])
                bc.coords("bar_fill", 0, 0, int(w * pct), _BAR_H)
                bc.itemconfigure("bar_fill", fill=clr)
            bar_canvas.bind("<Configure>", _bar_resize)
            bar_canvas._pct = 0.0
            bar_canvas._clr = T["accent"]

            def _update_card_bar(pct: float, color: str, bc=bar_canvas):
                bc._pct = pct
                bc._clr = color
                try:
                    w = max(bc.winfo_width(), 1)
                    bc.coords("bar_fill", 0, 0, int(w * pct), _BAR_H)
                    bc.itemconfigure("bar_fill", fill=color)
                except Exception:
                    pass

            if not hasattr(self, "_stage_bar_update"):
                self._stage_bar_update: dict[str, object] = {}
            self._stage_bar_update[key] = _update_card_bar
            # ────────────────────────────────────────────────────────────────

            def _apply_state(active):
                # Always read T[] live so theme changes are reflected correctly.
                _bg_on, _fg_on = T["accent"], T["button_fg"]
                _bg_off = T["surface2"]
                if active:
                    cell.configure(bg=_bg_on, highlightbackground=_bg_on); top.configure(bg=_bg_on)
                    badge.configure(text="✓", bg="#ffffff", fg=_bg_on)
                    name_lbl.configure(bg=_bg_on, fg=_fg_on); desc_lbl.configure(bg=_bg_on, fg=_fg_on)
                    bar_canvas.configure(bg=_bg_on)
                    bar_canvas.itemconfigure("bar_bg", fill="#ffffff30" if False else T["border"])
                else:
                    cell.configure(bg=_bg_off, highlightbackground=T["border"]); top.configure(bg=_bg_off)
                    badge.configure(text=num, bg=T["accent"], fg=T["button_fg"])
                    name_lbl.configure(bg=_bg_off, fg=T["text"]); desc_lbl.configure(bg=_bg_off, fg=T["muted"])
                    bar_canvas.configure(bg=_bg_off)
                    bar_canvas.itemconfigure("bar_bg", fill=T["border"])
                    # Refresh idle pill colours to match new theme
                    pill_text = pill.cget("text")
                    if pill_text == "● IDLE":
                        pill.configure(bg=T["pill_idle_bg"], fg=T["pill_idle_fg"])

            def _toggle(_evt=None):
                v = self._scan_vars[key]; v.set(0 if v.get() else 1)
                _apply_state(bool(v.get())); self._refresh_scan_btn()
                self._persist_scan_stages()   # remember selection as the new default

            def _on_enter(e):
                if not self._scan_vars[key].get(): cell.configure(highlightbackground=T["accent"])

            def _on_leave(e):
                if not self._scan_vars[key].get(): cell.configure(highlightbackground=T["border"])

            for w in cell.winfo_children() + [cell]:
                w.bind("<Button-1>", _toggle); w.bind("<Enter>", _on_enter); w.bind("<Leave>", _on_leave)
            self._stage_pills[key] = pill
            # Remember this card's paint function and sync it to the *actual*
            # BooleanVar value right away — without this, a stage whose var
            # defaults/was set to True (e.g. SCA + SAST) would still be drawn
            # "off", so the pipeline would silently run more (or fewer) stages
            # than the cards visually showed.
            self._stage_apply[key] = _apply_state
            _apply_state(bool(self._scan_vars[key].get()))

        for i, (k, n, nm, ds) in enumerate(_STAGES):
            _make_stage_card(k, n, nm, ds, i // 2, i % 2)

        prereq_outer = tk.Frame(cards_row, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
        prereq_outer.pack(side="left", fill="both", expand=True)
        self._prereq_hdr_frame = tk.Frame(prereq_outer, bg=T["accent"], padx=14, pady=5); self._prereq_hdr_frame.pack(fill="x")
        self._prereq_hdr_lbl = tk.Label(self._prereq_hdr_frame, text="PREREQUISITES", font=(_FUI, 10, "bold"),
                                        bg=T["accent"], fg=T["button_fg"], anchor="w"); self._prereq_hdr_lbl.pack(side="left")
        self._prereq_warn_lbl = tk.Label(self._prereq_hdr_frame, text="", font=(_FUI, 9, "bold"),
                                         bg=T["accent"], fg=T["button_fg"], anchor="e"); self._prereq_warn_lbl.pack(side="right")
        env_card = tk.Frame(prereq_outer, bg=T["panel_bg"], padx=10, pady=8); env_card.pack(fill="both", expand=True)

        # Python / Node / npm / Snyk-CLI are already installed by the boot
        # splash (_load_runtime) on every launch, so re-verifying them here is
        # redundant. Only authentication is left — the boot installer cannot log
        # you in, so a live Snyk session stays a mandatory, GUI-checked prereq.
        self._check_rows: dict[str, dict] = {}
        for key, name in [("auth", "Snyk authentication")]:
            row = tk.Frame(env_card, bg=T["panel_bg"]); row.pack(fill="x", pady=2)
            status = tk.Label(row, text="●", font=(_FUI, 12, "bold"), bg=T["panel_bg"], fg=T["muted"], width=2); status.pack(side="left")
            self._lbl(row, name, size=10, bold=True, width=16, anchor="w").pack(side="left")
            detail = self._lbl(row, "…", size=9, fg=T["muted"], anchor="w"); detail.pack(side="left", fill="x", expand=True, padx=(4, 4))
            fix = self._btn(row, "Fix", lambda k=key: self._fix(k), kind="outline"); fix.pack(side="right"); fix.config(state="disabled")
            self._check_rows[key] = {"status": status, "detail": detail, "fix": fix}

        btn_row_env = tk.Frame(env_card, bg=T["panel_bg"]); btn_row_env.pack(fill="x", pady=(4, 0))

        btn_row_env2 = tk.Frame(env_card, bg=T["panel_bg"]); btn_row_env2.pack(fill="x", pady=(6, 0))
        self._btn(btn_row_env2, '🔄 Re-check', lambda: self._run_async(self._recheck, label="env check"), kind="outline").pack(side="left")
        self._login_btn = self._btn(btn_row_env2, '🔑 Login via SSO',
                                    lambda: self._run_async(self._do_login, label="snyk auth"), kind="accent")
        self._login_btn.pack(side="left", padx=(8, 0)); self._login_btn.config(state="disabled")
        # Always-available re-login: a saved token can silently expire while the
        # panel still shows "logged in", so the user needs a way to force a fresh
        # SSO sign-in regardless of the panel's state.
        self._relogin_btn = self._btn(btn_row_env2, '🔁 Re-login (SSO)',
                                      lambda: self._run_async(self._do_login, label="snyk re-auth"),
                                      kind="outline")
        self._relogin_btn.pack(side="left", padx=(8, 0))

        self._scan_btn = tk.Button(pad, state="disabled")
        self._open_btn = tk.Button(pad, state="disabled")
        self._csv_btn = tk.Button(pad, state="disabled")
        self._recent_lb = tk.Listbox(pad); self._recent_lb.pack_forget()

    def _refresh_stage_cards(self):
        """Re-paint every pipeline stage card so it visually matches its
        BooleanVar — used after something other than a click changes
        _scan_vars (e.g. loading an app profile)."""
        for key, apply_fn in getattr(self, "_stage_apply", {}).items():
            try:
                apply_fn(bool(self._scan_vars[key].get()))
            except Exception:
                pass

    def _update_pipeline_progress(self, key: str, stage_label: str,
                                   granular_pct: float = -1.0):
        """Actualiza la barra de un card individual y la barra general del header PIPELINE.

        Llamado desde _drain_events en eventos 'stage' y 'progress'.
        stage_label: 'running' | 'done' | 'failed' | 'skipped' | 'idle'
        granular_pct: 0.0-1.0 cuando hay datos reales (DAST/API/Secrets).
                      -1.0 significa "usar valor por defecto según estado".
        """
        # ── Colores por estado ───────────────────────────────────────────────
        _bar_colors = {
            "running": T["pill_run_bg"],
            "done":    T["pill_ok_bg"],
            "failed":  T["pill_bad_bg"],
            "skipped": T["border"],
            "idle":    T["border"],
        }
        # Porcentajes por defecto cuando no hay datos granulares.
        # SCA/SAST: no exponen sub-progreso (Snyk CLI es opaco), usamos
        # indeterminate (0.15 para señalizar "corriendo", 1.0 al terminar).
        # Secrets/DAST/API: usan granular_pct cuando está disponible.
        _default_pcts = {
            "running": 0.15,
            "done":    1.0,
            "failed":  1.0,
            "skipped": 0.0,
            "idle":    0.0,
        }

        # Actualizar estado interno
        if not hasattr(self, "_pipe_stage_states"):
            self._pipe_stage_states = {}
        self._pipe_stage_states[key] = stage_label

        # Calcular pct real para este card
        if granular_pct >= 0.0:
            card_pct = granular_pct
        else:
            card_pct = _default_pcts.get(stage_label, 0.0)
        card_clr = _bar_colors.get(stage_label, T["border"])

        # Actualizar barra del card individual
        bar_fn = getattr(self, "_stage_bar_update", {}).get(key)
        if bar_fn:
            try:
                bar_fn(card_pct, card_clr)
            except Exception:
                pass

        # ── Progreso general del header PIPELINE ────────────────────────────
        # Usamos los pcts individuales almacenados para calcular el overall.
        # Inicializar tracking de pcts por card si no existe
        if not hasattr(self, "_pipe_card_pcts"):
            self._pipe_card_pcts: dict[str, float] = {}
        self._pipe_card_pcts[key] = card_pct

        selected = {k for k, v in getattr(self, "_scan_vars", {}).items() if v.get()}
        active_states = {k: v for k, v in self._pipe_stage_states.items() if k in selected}
        total = len(active_states)

        if total == 0:
            pct_general = 0.0
            txt_general = "— idle"
        else:
            # Promedio ponderado de los pcts individuales de los stages seleccionados
            pct_general = sum(
                self._pipe_card_pcts.get(k, _default_pcts.get(v, 0.0))
                for k, v in active_states.items()
            ) / total

            done_count    = sum(1 for s in active_states.values() if s in ("done", "failed"))
            skipped_count = sum(1 for s in active_states.values() if s == "skipped")
            running_count = sum(1 for s in active_states.values() if s == "running")
            finished      = done_count + skipped_count

            if finished == total:
                if done_count == total:
                    txt_general = f"✓ {done_count} / {done_count} completos"
                else:
                    txt_general = f"✓ {done_count} ok  {skipped_count} skip"
            elif running_count > 0:
                txt_general = f"⟳ {finished} / {total}  ({int(pct_general * 100)}%)"
            else:
                txt_general = f"— {total} en cola"

        self._pipe_progress_pct = pct_general
        try:
            cnv = self._pipe_hdr_canvas
            w = max(cnv.winfo_width(), 1)
            fill_clr = getattr(self, "_pipe_hdr_get_fill_color", lambda: "#b85c00")()
            cnv.coords("prog_rect", 0, 0, int(w * pct_general), 32)
            cnv.itemconfigure("prog_rect", fill=fill_clr)
            set_txt = getattr(self, "_pipe_hdr_set_prog_text", None)
            if set_txt:
                set_txt(txt_general)
        except Exception:
            pass

    def _refresh_scan_btn(self):
        if not hasattr(self, "_scan_btn"): return
        sel = {k for k, v in self._scan_vars.items() if v.get()}
        if not sel:
            self._scan_btn.config(state="disabled")
            if hasattr(self, "_run_icon_btn"):
                self._run_icon_btn.config(state="disabled", fg=T["muted"], highlightbackground=T["muted"],
                                          highlightcolor=T["muted"], bg=T["surface2"])
            return
        needs_snyk = bool({"sca","code"} & sel)
        checks = self._checks or {}
        auth_ok = bool(checks.get("auth") and checks["auth"].ok)
        ready = (not needs_snyk) or auth_ok
        self._scan_btn.config(state="normal" if ready else "disabled")
        if hasattr(self, "_run_icon_btn"):
            if ready:
                self._run_icon_btn.config(state="normal", fg=T["accent"], highlightbackground=T["accent"],
                                          highlightcolor=T["accent"], bg=T["panel_bg"],
                                          activebackground=T["surface2"], activeforeground=T["accent"])
            else:
                self._run_icon_btn.config(state="disabled", fg=T["muted"], highlightbackground=T["muted"],
                                          highlightcolor=T["muted"], bg=T["surface2"])

    def _recheck(self):
        # Deps (python/node/npm/snyk) are installed by the boot splash; only the
        # login state can change at runtime, so that's all we re-verify here.
        self._event_queue.put(("checks", {"auth": check_auth()}))

    def _apply_checks(self, results: dict[str, CheckResult]):
        self._checks = results
        for key, res in results.items():
            row = self._check_rows.get(key)
            if not row: continue
            row["status"].config(text="●", fg=T["ok"] if res.ok else (
                T["muted"] if not res.detail or res.detail == "…" else T["err"]))
            row["detail"].config(text=res.detail or ("ready" if res.ok else "not configured"))
            row["fix"].config(state="disabled" if (res.ok or not res.fixable) else "normal")

        auth_res = results.get("auth")
        auth_ok = bool(auth_res and auth_res.ok)

        # ── SSO enforcement: if authenticated but NOT via SSO/OAuth, reject it ──
        sso_ok = False
        if auth_ok:
            detail_low = (auth_res.detail or "").lower()
            if "sso" in detail_low or "oauth" in detail_low:
                sso_ok = True
            else:
                # Non-SSO token detected — treat as not-authenticated and warn
                auth_ok = False
                sso_ok = False
                row = self._check_rows.get("auth")
                if row:
                    row["status"].config(text="●", fg=T["err"])
                    row["detail"].config(text="⚠ Token detected — SSO required")
                    row["fix"].config(state="normal")
                self._log_line(
                    "[auth] ⚠ An API token was detected but NOT an SSO/OAuth session. "
                    "Click '🔁 Re-login (SSO)' and in the Snyk window choose "
                    "'Login via SSO' (the grayed-out option below 'Log in with Google'). "
                    "A plain token is not enough for organization scans.")

        prereq_hdr = getattr(self, "_prereq_hdr_frame", None)
        prereq_warn = getattr(self, "_prereq_warn_lbl", None)
        if prereq_hdr and prereq_warn:
            if not auth_ok:
                prereq_hdr.config(bg=T["err"]); prereq_warn.config(bg=T["err"], text="⚠ Action needed")
                hdr_lbl = getattr(self, "_prereq_hdr_lbl", None)
                if hdr_lbl: hdr_lbl.config(bg=T["err"])
            else:
                prereq_hdr.config(bg=T["accent"]); prereq_warn.config(bg=T["accent"], text="✔ Ready")
                hdr_lbl = getattr(self, "_prereq_hdr_lbl", None)
                if hdr_lbl: hdr_lbl.config(bg=T["accent"])
        if not auth_ok:
            self._login_btn.config(state="normal", text="🔑 Login via SSO")
        else:
            self._login_btn.config(state="disabled", text="✓ SSO Logged in")
        self._refresh_scan_btn()

    def _fix(self, key: str):
        if key in ("node", "npm", "snyk"):
            self._reinstall_missing_deps(key)
        elif key == "auth":
            self._run_async(self._do_login, label="snyk auth")

    def _reinstall_missing_deps(self, key: str):
        """Re-run the *full* boot installer (pip deps + Node/npm + git-secrets
        + Snyk CLI) inside the same BootSplash window used at startup, instead
        of installing just `key` inline/silently in the main window. Anything
        already satisfied is skipped quickly inside _load_runtime, so this
        stays cheap — but every install, first launch or later fix, always
        happens in that one globe-animation window."""
        if self._any_busy():
            self._log_line(f"[busy] ignoring fix for '{key}' — another op in progress"); return
        self._busy = True; self._update_stop_btn_style()
        self._set_status(f"Reinstalling dependencies ({key})…")
        try:
            err, warnings = run_boot(master=self)  # blocks here, but keeps the UI responsive
        finally:
            self._busy = False; self._update_stop_btn_style()
            self._set_status('Ready.'); self._refresh_scan_btn()
        if err:
            self._log_line(f"[fix] dependency install failed: {err.splitlines()[0]}")
        else:
            self._log_line(f"[fix] dependency check/install finished for '{key}'.")
        for label, detail in warnings:
            self._log_line(f"[fix] ⚠ {label}: {detail}")
        self._recheck()

    def _prompt_relogin(self):
        """Called (on the UI thread) when a scan fails because Snyk auth is
        stale/expired. Surface it loudly and point the user at re-login. Runs
        at most once per scan run so concurrent SCA+SAST failures don't stack."""
        if getattr(self, "_relogin_prompted", False):
            return
        self._relogin_prompted = True
        self._set_status("Snyk session expired — click 🔁 Re-login")
        self._log_line("[auth] ⚠ Snyk rejected the saved credential (expired or "
                       "invalid). Click 🔁 Re-login under ▶ Scan → Prerequisites "
                       "to sign in again through your organization's SSO, then "
                       "re-run the scan.")
        # Draw attention to the prereq panel + re-login button.
        try:
            hdr = getattr(self, "_prereq_hdr_frame", None)
            warn = getattr(self, "_prereq_warn_lbl", None)
            if hdr and warn:
                hdr.config(bg=T["err"]); warn.config(bg=T["err"], text="⚠ Re-login needed")
                lbl = getattr(self, "_prereq_hdr_lbl", None)
                if lbl: lbl.config(bg=T["err"])
            if getattr(self, "_relogin_btn", None):
                self._relogin_btn.config(state="normal")
        except Exception:
            pass

    def _do_login(self):
        # Each explicit login resets the one-shot re-login prompt guard.
        self._relogin_prompted = False
        if self._auth_proc and self._auth_proc.poll() is None:
            self._emit_log("[auth] cancelling previous auth attempt and starting a new one…")
            _kill_process_tree(self._auth_proc)
            self._auth_proc = None
        # Open the popup immediately so the user can read the instructions
        # while the CLI preparation runs in the background (can take 5–10 s).
        self.after(0, self._show_snyk_login_popup)

    def _show_snyk_login_popup(self):
        """Snyk login popup: shows Snyk.png + SSO instructions.

        Flow:
          1. Popup opens immediately (user can read instructions).
          2. CLI preparation (ensure_snyk_ready + clear_snyk_credentials) runs
             in a background thread while the user reads.
          3. User clicks 'Open browser' → spinner shown, browser opens once the
             CLI is ready; spinner hides when the process is launched.
          4. When auth is detected (_drain_events auth_check_done), the popup
             closes automatically via popup.close().
        """
        popup = self._create_popup("Log in to Snyk (SSO)", 0.48, 0.72)
        self._popup_hdr(popup, "Log in to Snyk", subtitle="SSO authentication", icon="🔑")
        body = tk.Frame(popup, bg=T["bg"]); body.pack(fill="both", expand=True)

        # ── Snyk.png image ─────────────────────────────────────────────────────
        img_frame = tk.Frame(body, bg=T["bg"]); img_frame.pack(pady=(14, 6))
        _img_ref = [None]
        img_path = SCRIPT_DIR / "Snyk.png"
        try:
            _img_ref[0] = tk.PhotoImage(file=str(img_path))
            w, h = _img_ref[0].width(), _img_ref[0].height()
            factor = max(1, max(w // 360, h // 230))
            if factor > 1:
                _img_ref[0] = _img_ref[0].subsample(factor, factor)
            img_lbl = tk.Label(img_frame, image=_img_ref[0], bg=T["bg"],
                               highlightthickness=1, highlightbackground=T["border"])
            img_lbl.image = _img_ref[0]   # keep reference
            img_lbl.pack()
        except Exception:
            tk.Label(img_frame, text="🔑", font=(_FUI, 52), bg=T["bg"], fg=T["accent"]).pack()

        # ── SSO instructions ───────────────────────────────────────────────────
        inst = tk.Frame(body, bg=T["panel_bg"], highlightthickness=1,
                        highlightbackground=T["border"], padx=20, pady=12)
        inst.pack(fill="x", padx=22, pady=(4, 12))
        tk.Label(inst, text="ℹ️  You must log in using SSO",
                 font=(_FUI, 11, "bold"), bg=T["panel_bg"], fg=T["accent"]).pack(anchor="w", pady=(0, 6))
        tk.Label(inst,
                 text=("In the Snyk window that opens in your browser:\n\n"
                       "  1. Click 'Log in with your company SSO' NOT Google or your credentials.\n"
                       "  2. Enter your organization's domain when prompted.\n"
                       "  3. Complete the authentication flow in the browser.\n"
                       "  4. Come back here — wait for the auth re-check to complete."),
                 font=(_FUI, 10), bg=T["panel_bg"], fg=T["text"],
                 justify="left", wraplength=440, anchor="w").pack(anchor="w")

        # ── State shared between closures ──────────────────────────────────────
        # _cli_ready[0]: True once the background CLI prep thread has finished.
        # _btn_clicked[0]: True once the user has pressed "Open browser".
        # _popup_closed[0]: True once close() has been called (prevents double-close).
        _cli_ready    = [False]
        _btn_clicked  = [False]
        _popup_closed = [False]
        open_btn_ref  = [None]
        spinner_lbl   = [None]

        # Store the popup close fn so _drain_events can call it on auth success.
        self._login_popup_close = None

        def _safe_close():
            if _popup_closed[0]:
                return
            _popup_closed[0] = True
            self._login_popup_close = None
            try:
                popup.close()
            except Exception:
                pass

        self._login_popup_close = _safe_close

        # ── Spinner animation ──────────────────────────────────────────────────
        _spinner_frames = ["◐", "◓", "◑", "◒"]
        _spinner_idx    = [0]
        _spinner_after  = [None]

        def _spinner_tick():
            lbl = spinner_lbl[0]
            if lbl is None:
                return
            try:
                _spinner_idx[0] = (_spinner_idx[0] + 1) % len(_spinner_frames)
                lbl.config(text=f"  {_spinner_frames[_spinner_idx[0]]}  opening browser, please wait")
                _spinner_after[0] = popup._win.after(160, _spinner_tick)
            except Exception:
                pass

        def _spinner_start():
            lbl = spinner_lbl[0]
            if lbl is None:
                return
            try:
                lbl.config(text=f"  {_spinner_frames[0]}  opening browser, please wait",
                           fg=T["accent"])
                lbl.pack(side="left")
            except Exception:
                pass
            _spinner_tick()

        def _spinner_stop():
            if _spinner_after[0]:
                try:
                    popup._win.after_cancel(_spinner_after[0])
                except Exception:
                    pass
                _spinner_after[0] = None
            lbl = spinner_lbl[0]
            if lbl is None:
                return
            try:
                lbl.pack_forget()
            except Exception:
                pass

        # ── Background CLI preparation ─────────────────────────────────────────
        def _prepare_cli():
            """Runs on a daemon thread: checks/repairs the Snyk CLI and clears
            stale credentials. Signals _cli_ready when done so _on_btn_ready
            can proceed immediately if the button was already clicked."""
            try:
                if not _which("snyk") or not ensure_snyk_ready(self._emit_log):
                    self._emit_log(
                        "[auth] Snyk CLI is not runnable yet — could not repair it "
                        "automatically. If your network uses a TLS-inspecting proxy, "
                        "set NODE_EXTRA_CA_CERTS to your company root CA .pem and retry."
                    )
                    # Even on failure, mark ready so the button is not stuck waiting.
                else:
                    clear_snyk_credentials(self._emit_log)
                    self._event_queue.put(("status", "Waiting for Snyk SSO authentication…"))
            except Exception as exc:
                self._emit_log(f"[auth] CLI preparation error: {exc!r}")
            finally:
                _cli_ready[0] = True
                # If the user already clicked the button while we were preparing,
                # schedule the browser launch on the UI thread now.
                if _btn_clicked[0]:
                    try:
                        popup._win.after(0, _launch_browser)
                    except Exception:
                        pass

        threading.Thread(target=_prepare_cli, daemon=True).start()

        # ── Browser launch (called on UI thread once CLI is ready) ─────────────
        def _launch_browser():
            _spinner_stop()
            self._auth_proc = start_snyk_auth(self._emit_log)
            self._auth_deadline = time.time() + AUTH_POLL_TIMEOUT
            self._auth_lines: queue.Queue = queue.Queue()
            proc_ref = self._auth_proc
            def _reader(proc=proc_ref):
                try:
                    if proc.stdout:
                        for line in iter(proc.stdout.readline, ""):
                            if not line:
                                break
                            self._auth_lines.put(line)
                except Exception:
                    pass
            threading.Thread(target=_reader, daemon=True).start()
            try:
                open_btn_ref[0].config(
                    state="disabled",
                    text="🌐  Browser opened — finish logging in there"
                )
            except Exception:
                pass

        # ── Button handler ─────────────────────────────────────────────────────
        def _open_browser():
            if _btn_clicked[0]:
                return
            _btn_clicked[0] = True
            # Disable the button immediately so it cannot be double-clicked.
            try:
                open_btn_ref[0].config(state="disabled")
            except Exception:
                pass
            if _cli_ready[0]:
                # CLI already prepared while the user was reading — go straight to launch.
                _launch_browser()
            else:
                # CLI still preparing — show spinner and wait.
                _spinner_start()

        # ── Footer (Close + Open browser) ─────────────────────────────────────
        foot_bar, _ = self._popup_foot(
            popup,
            ("  Close  ", _safe_close, "flat"),
            ("🌐  Open browser", _open_browser, "accent"),
            with_status=True,
        )
        # The with_status=True label is at index 0 of foot_bar's children;
        # re-use it as our spinner label so we don't need an extra frame.
        try:
            spinner_lbl[0] = foot_bar.winfo_children()[0]
            spinner_lbl[0].config(text="", font=(_FUI, 10))
        except Exception:
            pass
        # Keep a reference to the "Open browser" button for state changes.
        try:
            open_btn_ref[0] = foot_bar.winfo_children()[-1]
        except Exception:
            pass

    def _kick_auth_check(self):
        """Run check_auth() on a background thread. It shells out to the
        Snyk CLI, and while a 'snyk auth' login is also in-flight, the two
        can contend for the same credentials-file lock — so this call can
        block for as long as that lock is held, not just for the time of a
        normal CLI invocation. Calling it directly from _tick_auth_poll (UI
        thread) was exactly what made the whole window freeze, sometimes for
        a long time, instead of just the original few-hundred-ms blip."""
        if getattr(self, "_auth_check_inflight", False):
            return
        self._auth_check_inflight = True
        def _bg():
            try:
                res = check_auth()
            except Exception:
                res = None
            self._event_queue.put(("auth_check_done", res))
        threading.Thread(target=_bg, daemon=True).start()

    def _tick_auth_poll(self):
        proc = self._auth_proc
        if proc is None: return
        try:
            lines_q = getattr(self, "_auth_lines", None)
            while lines_q is not None:
                try:
                    line = lines_q.get_nowait()
                except queue.Empty:
                    break
                self._log_line(line.rstrip())
        except Exception: pass
        now = time.time()
        if not hasattr(self, "_next_auth_check") or now >= self._next_auth_check:
            self._next_auth_check = now + AUTH_POLL_INTERVAL
            self._kick_auth_check()
        if proc.poll() is not None:
            self._log_line(f"[auth] snyk auth exited ({proc.returncode})")
            self._auth_proc = None
            self._run_async(self._recheck, label="post-auth recheck"); return
        if now > self._auth_deadline:
            self._log_line("[auth] timeout — cancelling.")
            _kill_process_tree(proc)
            self._auth_proc = None

    def _start_scan(self):
        self._run_async(self._do_scan, label="full pipeline scan")

    def _request_cancel(self):
        if not self._any_busy():
            self._emit_log("[scan] nothing to cancel.")
            return
        self._show_confirm_popup(
            "Stop scan?",
            "A scan is currently running. Stopping now will discard any "
            "results not yet written to a report.\n\nDo you want to stop it?",
            on_yes=self._do_cancel,
            yes_label="  ■  Stop scan  ", no_label="  Keep running  ")

    def _do_cancel(self):
        if not self._any_busy():
            self._emit_log("[scan] nothing to cancel.")
            return
        # One Stop button, so it stops whichever lane(s) are actually
        # running — setting an Event that nothing is listening for is a
        # harmless no-op, so it's safe to signal both unconditionally.
        if self._busy: self._cancel_evt.set()
        if self._static_busy: self._static_cancel_evt.set()
        self._emit_log("[scan] cancel requested…"); self._set_status('Cancelling…')
        try:
            import audit_log
            audit_log.write_event(Path(self._reports_var.get()), "scan_cancel_requested",
                                  actor=self._user, log=self._emit_log)
        except Exception: pass

    def _scoped_report_paths(self, reports_root: Path):
        """Return (report_label, app_reports_root) scoped to the active app.

        Centralises the slug/label/folder logic previously duplicated across the
        scan pipelines. app_reports_root is created on disk before returning.
        """
        active_app = getattr(self, "_active_app", None)
        slug = (_re.sub(r"[^A-Za-z0-9\-_]", "_", active_app["name"].strip())
                if active_app and active_app.get("name") else "")
        label = f"{self._user}+{slug}" if slug else self._user
        app_reports_root = reports_root / (slug if slug else "_unscoped")
        app_reports_root.mkdir(parents=True, exist_ok=True)
        return label, app_reports_root

    def _do_scan(self):
        selected = {k for k, v in self._scan_vars.items() if v.get()}
        if not selected:
            self._emit_log("[scan] nothing selected"); return
        self._cancel_evt.clear()
        target = Path(self._target_var.get()).resolve()
        reports_root = Path(self._reports_var.get()).resolve(); reports_root.mkdir(parents=True, exist_ok=True)
        if bool({"sca","code"} & selected) and (not target.exists() or not target.is_dir()):
            self._emit_log(f"[scan] target folder missing: {target}"); return
        mode = "+".join(sorted(selected))
        active_app = getattr(self, "_active_app", None)  # report label: "user+AppName" when an app is loaded
        _report_label, app_reports_root = self._scoped_report_paths(reports_root)
        out_dir = app_reports_root / f"report_{_ts()}_{mode}"; out_dir.mkdir(parents=True, exist_ok=True)
        self._session_begin("pipeline", selected)   # crash-recovery marker
        import audit_log
        audit_log.write_event(reports_root, "scan_start", actor=self._user,
                              app=(active_app.get("name") if active_app else ""),
                              mode=mode, target=str(target), out_dir=str(out_dir),
                              log=self._emit_log)
        self._emit_log(f"[scan] pipeline: {mode.upper()}")
        self._emit_log(f"[scan] output → {out_dir}")
        _snyk_usable = True
        if {"sca", "code"} & selected:
            try:
                if not ensure_snyk_ready(self._emit_log):
                    _snyk_usable = False
                    self._emit_log("[scan] Snyk CLI is not runnable — skipping "
                                   "SCA/SAST. Click Fix to repair it.")
            except Exception as e:
                self._emit_log(f"[scan] snyk readiness check error: {e!r}")
        try: v = _run(["snyk","--version"]).stdout.strip()
        except Exception: v = "?"
        results: dict[str, Any] = {"sca":None,"code":None,"dast":None,"api":None,"secrets":None}
        # Resetear visualmente todas las barras de progreso antes de iniciar
        self._event_queue.put(("pipeline_reset", None))
        for k in ("sca","code","dast","api","secrets"):
            running = k in selected and (_snyk_usable or k not in ("sca", "code"))
            self._event_queue.put(("stage", (k, "running" if running else "skipped")))
        jobs: list[tuple[str, Callable[[], None]]] = []
        def _stage(key, fn, *a, **kw):
            jobs.append((key, lambda: results.__setitem__(key, fn(*a, **kw)[0])))
        if "sca" in selected and _snyk_usable: _stage("sca", run_snyk_test, target, out_dir, self._emit_log)
        if "code" in selected and _snyk_usable: _stage("code", run_snyk_code, target, out_dir, self._emit_log)
        if "dast" in selected:
            dast_cfg = self._collect_dast_cfg()
            if not dast_cfg.url or dast_cfg.url == "https://":
                self._emit_log("[dast] no URL configured — skipping DAST")
                self._event_queue.put(("stage",("dast","skipped")))
            else:
                _stage("dast", run_dast, dast_cfg, out_dir, self._emit_log, cancel=self._cancel_evt,
                       progress=lambda n, t: self._event_queue.put(("progress", ("DAST", n, t))))
        if "api" in selected:
            api_cfg = self._collect_api_cfg()
            if not api_cfg.spec_source:
                self._emit_log("[api] no spec configured — skipping API scan")
                self._event_queue.put(("stage",("api","skipped")))
            else:
                _stage("api", run_api, api_cfg, out_dir, self._emit_log, cancel=self._cancel_evt,
                       progress=lambda n, t: self._event_queue.put(("progress", ("API", n, t))))
        if "secrets" in selected:
            def _run_secrets_stage():
                try:
                    self._emit_log("[secrets] running secret scan as pipeline stage…")
                    # Pre-contar archivos candidatos para progreso granular.
                    # _iter_files hace el mismo walk que _scan_builtin.
                    _total_files = [0]
                    try:
                        import os as _os
                        for _dp, _dns, _fns in _os.walk(str(target)):
                            _dns[:] = [d for d in _dns
                                       if d == ".github" or (d not in
                                       getattr(scan_path, "_SKIP_DIRS",
                                               {"node_modules","dist","build",".git",
                                                "vendor","__pycache__",".venv","venv",
                                                ".tox",".eggs","*.egg-info"})
                                       and not d.startswith("."))]
                            _total_files[0] += len(_fns)
                    except Exception:
                        _total_files[0] = 0

                    # Wrapper de log que intercepta la línea de conteo de scanned
                    # que _scan_builtin emite tras cada actualización de stats.
                    _scanned_ref = [0]
                    def _progress_log(msg: str):
                        self._emit_log(msg)
                        # "secrets] built-in engine: N file(s) seen · M scanned"
                        # Usamos el conteo acumulado del log para emitir progreso
                        if "[secrets] built-in" in msg and "scanned" in msg:
                            try:
                                # Extraer "M scanned" del mensaje
                                parts = msg.split("·")
                                for p in parts:
                                    if "scanned" in p:
                                        n = int(p.strip().split()[0])
                                        _scanned_ref[0] = n
                                        if _total_files[0] > 0:
                                            pct = min(n / _total_files[0], 0.99)
                                            self._event_queue.put(("progress",
                                                                    ("Secrets", n, _total_files[0])))
                                        break
                            except Exception:
                                pass

                    result = scan_path(target, _progress_log, cancel=self._cancel_evt,
                                       git_secrets_status=get_git_secrets_status())
                    sec_dir = out_dir / "secrets"
                    write_secrets_report(result, sec_dir)
                    self._emit_log(f"[secrets] {result['total']} finding(s) across {result['scanned_files']} file(s)")
                    results["secrets"] = result
                except Exception as e:
                    self._emit_log(f"[secrets] stage failed: {e!r}"); results["secrets"] = None
            jobs.append(("secrets", _run_secrets_stage))
        def run_stage(item):
            key, fn = item
            try:
                fn(); self._event_queue.put(("stage",(key,"done")))
            except Exception as e:
                self._event_queue.put(("stage",(key,"failed"))); self._emit_log(f"[scan] {key} failed: {e!r}")
                if getattr(e, "is_auth", False):
                    self._event_queue.put(("auth_required", None))
        if len(jobs) > 1:
            self._emit_log(f"[scan] running {len(jobs)} stages concurrently")
            with ThreadPoolExecutor(max_workers=len(jobs)) as ex_:
                list(ex_.map(run_stage, jobs))
        else:
            for j in jobs: run_stage(j)
        # Persist each completed stage so the next report always includes the last run of EVERY type.
        dast_url_hint = ""; api_spec_hint = ""
        try: dast_url_hint = self._dast_url_var.get().strip()
        except Exception: pass
        try: api_spec_hint = self._api_spec_var.get().strip()
        except Exception: pass
        _kind_targets = {
            "sca": str(target), "code": str(target), "dast": dast_url_hint or str(target),
            "api": api_spec_hint or str(target), "secrets": str(target),
        }
        state = self._scan_state
        for kind in ("sca", "code", "dast", "api", "secrets"):
            raw = results.get(kind)
            if raw is not None:
                try:
                    state.save_kind(kind, raw, target=_kind_targets.get(kind, str(target)),
                                    snyk_version=v, mode=mode)
                    self._emit_log(f"[state] {kind} result persisted to cumulative store")
                except Exception as e:
                    self._emit_log(f"[state] could not save {kind}: {e!r}")
        ctx = build_cumulative_context(state, target_hint=target, snyk_version_hint=v, current_results=results)
        self._emit_log("[report] building cumulative report (all scan types merged)")
        ctx["scan_mode"] = mode
        self._emit_log(f"[scan] cumulative total: {ctx['total']}  "
                       f"crit={ctx['counts']['critical']}  high={ctx['counts']['high']}  "
                       f"med={ctx['counts']['medium']}  low={ctx['counts']['low']}  "
                       f"secrets={ctx.get('secrets_total',0)}")
        _base = _report_basename(self._user, mode)
        report = render_html(ctx, out_dir, filename=f"{_base}.html")
        csv_path = export_csv(ctx, out_dir / f"{_base}.csv", report_label=_report_label)
        self._emit_log(f"[report] CSV bundle (ZIP): {csv_path}  (sca/sast/dast/api/secrets sheets + summary)")
        sec_html_src = out_dir / "secrets" / "secrets.html"
        if sec_html_src.exists():
            try:
                sec_html_dst = out_dir / f"{_base}_secrets.html"
                shutil.copyfile(sec_html_src, sec_html_dst)
                self._emit_log(f"[report] Secrets HTML → {sec_html_dst}")
            except Exception as e:
                self._emit_log(f"[report] secrets HTML copy skipped: {e!r}")
        try:
            sarif_path = export_sarif(out_dir)
            if sarif_path: self._emit_log(f"[report] SARIF: {sarif_path}")
        except Exception as e:
            self._emit_log(f"[report] SARIF export skipped: {e!r}")
        try:
            merged_path = export_merged_json(out_dir)
            if merged_path: self._emit_log(f"[report] merged JSON: {merged_path}")
        except Exception as e:
            self._emit_log(f"[report] merged JSON skipped: {e!r}")
        meta = {
            "generated_at": ctx["generated_at"], "target": ctx["target"], "mode": mode,
            "counts": ctx["counts"], "total": ctx["total"], "sca_total": ctx["sca_total"],
            "code_total": ctx["code_total"], "dast_total": ctx.get("dast_total",0),
            "api_total": ctx.get("api_total",0), "snyk_version": ctx["snyk_version"],
            "secrets_total": ctx.get("secrets_total", 0),
        }
        (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        try:
            rec = update_history_after_scan(reports_root, ctx, meta,
                                            actor=getattr(self, "_user", ""), report_dir=out_dir)
            self._emit_log(f"[history] recorded scan — remediated {rec.get('remediated_count',0)}, "
                           f"new {rec.get('introduced_count',0)} since last {mode.upper()} run")
        except Exception as e:
            self._emit_log(f"[history] could not update remediation history: {e!r}")
        active_app = getattr(self, "_active_app", None)
        if active_app and active_app.get("id"):
            try:
                self._inv_store.record_scan(active_app["id"], meta)
                self._emit_log(f"[inventory] scan recorded for app '{active_app['name']}'")
                self._event_queue.put(("inv_refresh", active_app["id"]))
            except Exception as e:
                self._emit_log(f"[inventory] could not update app record: {e!r}")
        c = ctx["counts"]
        secrets_crit = sum(1 for s in ctx.get("secrets", {}).get("findings", [])
                           if s.get("severity") in ("critical", "high"))
        gate = "FAIL" if (c.get("critical",0) or c.get("high",0) or secrets_crit) else "PASS"
        self._emit_log(f"[gate] {gate}  (critical={c.get('critical',0)} high={c.get('high',0)} "
                       f"medium={c.get('medium',0)} low={c.get('low',0)} "
                       f"secrets_crit_high={secrets_crit})")
        self._last_context = ctx; self._last_report_dir = out_dir
        self._last_static_report = Path(report)
        self._emit_log(f"[report] HTML: {report}")
        self._emit_log(f"[report] CSV:  {csv_path}")
        audit_log.write_event(reports_root, "scan_end", actor=self._user,
                              app=(active_app.get("name") if active_app else ""),
                              mode=mode, total=ctx["total"], counts=ctx["counts"],
                              gate=gate, secrets_crit_high=secrets_crit,
                              report=str(report), cancelled=self._cancel_evt.is_set(),
                              log=self._emit_log)
        self._event_queue.put(("static_results", ctx))  # refresh Static-tab trees
        self._event_queue.put(("report", str(report)))
        self._session_end("pipeline")   # clean completion — clear crash-recovery marker
