from __future__ import annotations

"""ScannerApp mixin: the DAST tab -- target/auth config, the Selenium login/logout macro recorder, and the field-persistence wiring for everything on this tab.

Lives in its own file purely for editor sanity -- this is still
logically part of Snyk_Scanner_GUI.py: it shares that module's globals
(T, fonts, helper functions, the runtime-injected engine calls) via
_wire_mixin_globals(), the same trick _load_runtime() already uses to
pull static_scanner/dast_api/report_engine symbols into this module.
Do not import this file standalone or instantiate this class on its
own -- it has no meaning outside being mixed into ScannerApp."""

class _DastTabMixin:
    _CRED_KEYS = [
        "username", "password", "token", "cookie", "header_name", "header_value",
        "login_url", "login_data", "selenium_login_url", "selenium_user_selector",
        "selenium_user_value", "selenium_pass_selector", "selenium_pass_value",
        "selenium_submit_selector", "selenium_extra_steps", "selenium_macro",
        "login_success_selector", "login_success_text", "logout_url_re",
        "selenium_logout_macro",
    ]
    _DAST_AUTH_FIELDS = {
        "auto":     [("username", "Username", False), ("password", "Password", True),
                     ("selenium_login_url", "Login page URL (optional)", False)],
        "none":     [],
        "basic":    [("username", "Username", False), ("password", "Password", True)],
        "bearer":   [("token", "Bearer token", True)],
        "cookie":   [("cookie", "Cookie header value", False)],
        "header":   [("header_name", "Header name", False), ("header_value", "Header value", True)],
        "form":     [("username", "Username", False), ("password", "Password", True),
                     ("login_url", "Login POST URL", False), ("login_data", "POST body", False)],
        "selenium": [("selenium_login_url", "Login page URL", False),
                     ("selenium_user_selector", "Username CSS selector", False),
                     ("selenium_user_value", "Username value", False),
                     ("selenium_pass_selector", "Password CSS selector", False),
                     ("selenium_pass_value", "Password value", True),
                     ("selenium_submit_selector", "Submit CSS selector", False),
                     ("selenium_extra_steps", "Extra steps JSON", False)],
    }
    _SESSION_FIELDS = [
        ("login_success_selector", "Logged-in CSS selector"),
        ("login_success_text",     "Logged-in text marker"),
        ("logout_url_re",          "Logout URL regex"),
    ]
    _LOGIN_CONDITION_KEYS = [
        "selenium_login_url", "selenium_user_selector", "selenium_user_value",
        "selenium_pass_selector", "selenium_submit_selector", "selenium_extra_steps",
        "selenium_macro", "login_success_selector", "login_success_text",
    ]
    _LOGOUT_CONDITION_KEYS = ["logout_url_re", "login_success_selector",
                              "login_success_text", "selenium_logout_macro"]
    _SECRET_KEYS = {"password", "token", "cookie", "header_value",
                    "selenium_pass_value", "login_data"}

    def _build_tab_dast(self, parent):
        self._section_header(parent, '🌐  Dynamic Application Security Testing (DAST)')
        pad = self._scrollable(parent)
        self._safety_banner(pad,
            "Active probes (XSS / SQLi / open-redirect / auth-bypass) and the login/logout "
            "macro replay send real traffic to the Target URL below. Confirm this points to a "
            "non-production environment before you run a scan.")
        body = self._card(pad, 'TARGET & PROFILE'); body.columnconfigure(1, weight=1)
        def gl(text, r, c): return self._glabel(body, text, r, c)
        gl('Target URL', 0, 0); self._gentry(body, self._dast_url_var, 0, 1, span=3)
        gl('Auth type', 1, 0)
        ac = ttk.Combobox(body, textvariable=self._dast_auth_var,
                          values=["auto","none","basic","bearer","cookie","header","form","selenium"],
                          state="readonly", width=12)
        ac.grid(row=1, column=1, sticky="w", pady=3)
        def _on_dast_auth_change(_evt=None): self._refresh_dast_creds(); self._refresh_dast_sel_card()
        ac.bind("<<ComboboxSelected>>", _on_dast_auth_change)
        gl('Profile', 2, 0)
        pc = ttk.Combobox(body, textvariable=self._dast_profile_var, values=["passive","active"],
                          state="readonly", width=10)
        pc.grid(row=2, column=1, sticky="w", pady=3, padx=(0, 4))
        self._dast_cred_frame = tk.Frame(body, bg=T["panel_bg"])
        self._dast_cred_frame.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(4, 0))
        self._dast_cred_frame.columnconfigure(1, weight=1)
        scope = tk.Frame(body, bg=T["panel_bg"]); scope.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        self._spin(scope, 'Max pages', self._dast_pages_var, 1, 500, width=5, padx=(0, 14))
        for text, var, _ in [
            ("Include subdomains", self._dast_subs_var,    'Also crawl links on subdomains of the target host.'),
            ("Verify TLS",         self._dast_tls_var,     'Validate HTTPS certificate. Untick for self-signed / staging certs.'),
            ("Auto re-login",      self._dast_relogin_var, 'Re-authenticate automatically if the session expires mid-scan.'),
        ]:
            ttk.Checkbutton(scope, text=text, variable=var).pack(side="left", padx=(0, 14))
        adv = tk.Frame(body, bg=T["panel_bg"]); adv.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(6, 0))
        adv.columnconfigure(1, weight=2); adv.columnconfigure(3, weight=1)
        self._lbl(adv, 'Exclude URL regex', size=10, fg=T["muted"]).grid(row=0, column=0, sticky="w", padx=(0, 6))
        self._gentry(adv, self._dast_exclude_var, 0, 1, span=3)
        rps_row = tk.Frame(body, bg=T["panel_bg"]); rps_row.grid(row=6, column=0, columnspan=4, sticky="ew", pady=(4, 0))
        self._spin(rps_row, 'Rate (req/s)', self._dast_rps_var, 0.5, 100, inc=0.5, padx=(0, 16))
        self._spin(rps_row, 'Workers', self._dast_workers_var, 1, 16, width=4, padx=(0, 16))
        self._lbl(rps_row, 'HTTP proxy', size=10, fg=T["muted"]).pack(side="left", padx=(0, 4))
        ttk.Entry(rps_row, textvariable=self._dast_proxy_var, width=28).pack(side="left")
        sel_card = self._card(pad, 'BROWSER LOGIN  (auth = auto / selenium)', pady=(0, 14)); sel_card.columnconfigure(1, weight=1)
        self._lbl(sel_card, 'Browser', size=10, fg=T["muted"]).grid(row=1, column=0, sticky="e", padx=(0, 6))
        labels = self._refresh_browser_catalog()  # only browsers installed on this machine
        sel_browser_cb = ttk.Combobox(sel_card, textvariable=self._dast_browser_label_var,
                                      values=labels, state="readonly", width=18)
        sel_browser_cb.grid(row=1, column=1, sticky="w"); self._dast_browser_cb = sel_browser_cb
        def _on_browser_pick(_=None):
            key = self._browser_label_key.get(self._dast_browser_label_var.get())
            if key: self._dast_browser_var.set(key)
        sel_browser_cb.bind("<<ComboboxSelected>>", _on_browser_pick)
        sel_opts = tk.Frame(sel_card, bg=T["panel_bg"]); sel_opts.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(4, 0))
        ttk.Checkbutton(sel_opts, text="Headless", variable=self._dast_headless_var)
        self._spin(sel_opts, 'Login timeout (s)', self._dast_selwait_var, 1, 180, width=5, padx=(0, 16))
        macro_row = tk.Frame(sel_card, bg=T["panel_bg"]); macro_row.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        self._dast_macro_row = macro_row
        tk.Frame(macro_row, bg=T["border"], height=1).pack(fill="x", pady=(0, 8))
        self._lbl(macro_row, "MACROS", size=9, fg=T["muted"], bold=True).pack(anchor="w")
        macro_btns = tk.Frame(macro_row, bg=T["panel_bg"]); macro_btns.pack(fill="x", pady=(4, 0))
        self._macro_recorded = {"login": False, "logout": False}
        self._macro_check_vars = {"login": tk.StringVar(value=""), "logout": tk.StringVar(value="")}

        def _refresh_macro_ui():
            for flag, var in self._macro_check_vars.items():
                var.set("  ✔" if self._macro_recorded[flag] else "")
            lo_btn = getattr(self, "_macro_logout_btn", None)
            if lo_btn: lo_btn.config(state="normal" if self._macro_recorded["login"] else "disabled")
            both = self._macro_recorded["login"] and self._macro_recorded["logout"]
            tst_btn = getattr(self, "_macro_test_btn", None)
            if tst_btn: tst_btn.config(state="normal" if both else "disabled")

        def _macro_popup(flag, title, icon, desc, record_fn, save_fn, load_fn, rec_tip, save_tip, load_tip):
            popup = self._create_popup(title)
            self._popup_hdr(popup, title, icon=icon)
            body2 = tk.Frame(popup, bg=T["bg"]); body2.pack(fill="both", expand=True)
            tk.Frame(body2, bg=T["bg"]).pack(fill="both", expand=True)
            recorded_now = self._macro_recorded[flag]
            badge_var = tk.StringVar(value="✔  Recorded" if recorded_now else "⬜  Not recorded")
            badge_fg = T["ok"] if recorded_now else T["muted"]
            stat_frame = tk.Frame(body2, bg=T["panel_bg"], highlightthickness=1, highlightbackground=T["border"])
            stat_frame.pack(fill="x", padx=60)
            stat_inner = tk.Frame(stat_frame, bg=T["panel_bg"], padx=28, pady=14); stat_inner.pack(fill="x")
            badge_lbl = tk.Label(stat_inner, textvariable=badge_var, font=(_FUI, 16, "bold"), bg=T["panel_bg"], fg=badge_fg)
            badge_lbl.pack(side="left")
            tk.Label(stat_inner, text=desc, font=(_FUI, 11), bg=T["panel_bg"], fg=T["muted"],
                     justify="left", wraplength=900).pack(side="left", padx=(28, 0))
            card_row = tk.Frame(body2, bg=T["bg"]); card_row.pack(padx=60, pady=28)
            tk.Frame(body2, bg=T["bg"]).pack(fill="both", expand=True)

            def _do_record():
                popup.close(); ok = record_fn()
                if ok:
                    self._macro_recorded[flag] = True; _refresh_macro_ui()

            def _do_load():
                popup.close(); load_fn()
                check_key = "selenium_login_url" if flag == "login" else "logout_url_re"
                if self._dast_cred_vars.get(check_key, tk.StringVar()).get().strip():
                    self._macro_recorded[flag] = True; _refresh_macro_ui()

            def _do_clear():
                _CLEAR_KEYS = {
                    "login":  ["selenium_login_url","selenium_user_selector","selenium_user_value",
                               "selenium_pass_selector","selenium_pass_value","selenium_submit_selector",
                               "selenium_extra_steps","selenium_macro","login_success_selector","login_success_text"],
                    "logout": ["logout_url_re","login_success_selector","login_success_text"],
                }
                for k in _CLEAR_KEYS.get(flag, []):
                    if k in self._dast_cred_vars: self._dast_cred_vars[k].set("")
                self._macro_recorded[flag] = True   # keep logic compatible
                self._macro_recorded[flag] = False
                if flag == "login":
                    for k in _CLEAR_KEYS["logout"]:
                        if k in self._dast_cred_vars: self._dast_cred_vars[k].set("")
                    self._macro_recorded["logout"] = False
                _refresh_macro_ui(); self._refresh_dast_creds()
                badge_var.set("⬜  Not recorded"); badge_lbl.config(fg=T["muted"]); popup.close()

            def _do_test_logout():
                popup.close(); self._dast_test_logout()

            _actions = [
                ("⏺", "Record new", rec_tip, _do_record, True, "accent"),
                ("💾", "Save…", save_tip, lambda: (popup.close(), save_fn()), recorded_now, "outline"),
                ("📂", "Load…", load_tip, _do_load, True, "outline"),
                ("🗑", "Clear", f"Reset the {flag} condition and clear all stored selectors.",
                 _do_clear, recorded_now, "flat"),
            ]
            if flag == "logout":
                _actions.append(("🧪", "Test",
                    "Open a browser, replay login, navigate to the logout URL, then close automatically.",
                    _do_test_logout, self._macro_recorded["logout"], "outline"))
            for ico, lbl, tip, cmd, enabled, _kind in _actions:
                card = self._choice_card(card_row, ico, lbl, tip, enabled=enabled, icon_size=32,
                                         title_size=13, desc_size=9, desc_wrap=170, ipadx=18, ipady=12,
                                         padx=10, icon_pady=(16, 6), desc_pady=(4, 16))
                if enabled:
                    def _mk(c=cmd):
                        def _fn(e=None): c()
                        return _fn
                    fn = _mk(); card.bind("<Button-1>", fn)
                    for child in card.winfo_children(): child.bind("<Button-1>", fn)
                    card.bind("<Enter>", lambda e, c=card: c.configure(highlightbackground=T["accent"]))
                    card.bind("<Leave>", lambda e, c=card: c.configure(highlightbackground=T["border"]))
            self._popup_foot(popup, ("  Close  ", popup.close, "flat"))

        login_wrap = tk.Frame(macro_btns, bg=T["panel_bg"]); login_wrap.pack(side="left", padx=(0, 4))
        login_args = ("login", "Login Macro", "⏺",
                      "Record a new macro, or save/load a previously recorded one.",
                      self._dast_record_macro, self._dast_save_login_condition, self._dast_load_login_condition,
                      "Opens a real browser and records your login clicks and form inputs.",
                      "Save the recorded login selectors + session-detection fields.\nPasswords are never written to disk.",
                      "Load a previously saved login-condition file.")
        login_btn = self._btn(login_wrap, "⏺  Record Login Condition", lambda a=login_args: _macro_popup(*a), kind="outline")
        login_btn.pack(side="left")
        tk.Label(login_wrap, textvariable=self._macro_check_vars["login"], font=(_FUI, 11, "bold"),
                 bg=T["panel_bg"], fg=T["ok"]).pack(side="left")
        logout_wrap = tk.Frame(macro_btns, bg=T["panel_bg"]); logout_wrap.pack(side="left", padx=(4, 0))
        logout_args = ("logout", "Logout Condition", "🚪",
                       "Record a logout condition, or save/load a previously recorded one.",
                       self._dast_record_logout, self._dast_save_logout_condition, self._dast_load_logout_condition,
                       "Opens a browser, replays your login, then records the logout state.",
                       "Save the logout URL regex + logged-in selector & text marker.",
                       "Load a saved logout-condition file.")
        logout_btn = self._btn(logout_wrap, "🚪  Record Logout Condition", lambda a=logout_args: _macro_popup(*a), kind="outline")
        logout_btn.pack(side="left"); logout_btn.config(state="disabled")
        tk.Label(logout_wrap, textvariable=self._macro_check_vars["logout"], font=(_FUI, 11, "bold"),
                 bg=T["panel_bg"], fg=T["ok"]).pack(side="left")
        test_btn = self._btn(logout_wrap, "🧪  Test", self._dast_test_logout, kind="outline")
        test_btn.pack(side="left", padx=(8, 0))
        test_btn.config(state="disabled")
        self._macro_logout_btn = logout_btn
        self._macro_test_btn   = test_btn
        prof_row = tk.Frame(pad, bg=T["bg"])
        # Save Profile / Load Profile removed: fields auto-persist via _save_settings().
        # prof_row kept as a structural anchor in case of future additions; not packed.
        self._dast_sel_card = sel_card; self._dast_prof_row = prof_row
        self._refresh_dast_creds(); self._refresh_dast_sel_card()
        # Wire auto-persistence: save whenever any DAST variable changes.
        self._setup_dast_field_persistence()

    def _refresh_creds(self, frame, auth_var, cred_vars, *, session_fields=False):
        for w in frame.winfo_children(): w.destroy()
        frame.columnconfigure(1, weight=1)
        kind = auth_var.get()
        base = 0
        if kind == "auto":
            self._lbl(frame,
                      "Auto-detects the login form in a real browser, fills these "
                      "credentials, submits and verifies — no selectors or macro needed.",
                      size=9, fg=T["muted"], anchor="w", wraplength=520
                      ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))
            base = 1
        fields = [f for f in self._DAST_AUTH_FIELDS.get(kind, []) if f[0] in cred_vars]
        for i, (key, label, secret) in enumerate(fields):
            r = base + i
            self._lbl(frame, label, size=10, fg=T["muted"], anchor="e").grid(row=r, column=0, sticky="e", padx=(0, 6), pady=2)
            ttk.Entry(frame, textvariable=cred_vars[key], show="*" if secret else "").grid(row=r, column=1, sticky="ew", pady=2)
        if session_fields:
            r0 = base + len(fields)
            tk.Frame(frame, bg=T["border"], height=1).grid(row=r0, column=0, columnspan=2, sticky="ew", pady=6); r0 += 1
            self._lbl(frame, "SESSION DETECTION", size=9, fg=T["muted"], bold=True).grid(row=r0, column=0, columnspan=2, sticky="w"); r0 += 1
            for key, label in self._SESSION_FIELDS:
                self._lbl(frame, label, size=10, fg=T["muted"], anchor="e").grid(row=r0, column=0, sticky="e", padx=(0, 6), pady=2)
                ttk.Entry(frame, textvariable=cred_vars[key]).grid(row=r0, column=1, sticky="ew", pady=2); r0 += 1

    def _refresh_dast_creds(self):
        self._refresh_creds(self._dast_cred_frame, self._dast_auth_var, self._dast_cred_vars, session_fields=True)

    def _refresh_dast_sel_card(self):
        kind = self._dast_auth_var.get()
        show = kind in ("selenium", "auto")
        outer = self._dast_sel_card.master
        if show: outer.pack(fill="x", pady=(0, 14))
        else:    outer.pack_forget()
        # MACROS (record login/logout) only make sense for the manual selenium
        # flow — "auto" detects everything on its own, so hide them there.
        mrow = getattr(self, "_dast_macro_row", None)
        if mrow is not None:
            if kind == "selenium": mrow.grid()
            else:                  mrow.grid_remove()

    def _collect_dast_cfg(self) -> DastConfig:
        v = self._dast_cred_vars; g = lambda k: v[k].get()
        browser_key = self._dast_browser_var.get() or "chrome"
        browser_bin = (self._browser_catalog.get(browser_key, {}) or {}).get("binary", "")
        return DastConfig(
            url=self._dast_url_var.get().strip(), auth_type=self._dast_auth_var.get(),
            username=g("username"), password=g("password"), token=g("token"),
            cookie=g("cookie"), header_name=g("header_name"), header_value=g("header_value"),
            login_url=g("login_url"), login_data=g("login_data"), profile=self._dast_profile_var.get(),
            max_pages=int(self._dast_pages_var.get() or 30), verify_tls=bool(self._dast_tls_var.get()),
            include_subdomains=bool(self._dast_subs_var.get()), selenium_browser=browser_key,
            selenium_binary=browser_bin, selenium_headless=bool(self._dast_headless_var.get()),
            selenium_wait_seconds=int(self._dast_selwait_var.get() or 15),
            selenium_login_url=g("selenium_login_url"), selenium_user_selector=g("selenium_user_selector"),
            selenium_user_value=g("selenium_user_value"), selenium_pass_selector=g("selenium_pass_selector"),
            selenium_pass_value=g("selenium_pass_value"), selenium_submit_selector=g("selenium_submit_selector"),
            selenium_extra_steps=g("selenium_extra_steps"), selenium_macro=g("selenium_macro"),
            selenium_logout_macro=g("selenium_logout_macro"), login_success_selector=g("login_success_selector"),
            login_success_text=g("login_success_text"), logout_url_re=g("logout_url_re"),
            auto_relogin=bool(self._dast_relogin_var.get()), exclude_re=self._dast_exclude_var.get(),
            rate_limit_rps=float(self._dast_rps_var.get() or 8.0),
            concurrency=int(self._dast_workers_var.get() or 4), proxy=self._dast_proxy_var.get())

    def _dast_save_profile(self):
        cfg = self._collect_dast_cfg()
        data = {k: v for k, v in cfg.__dict__.items() if k not in ("password","token","selenium_pass_value")}
        path = filedialog.asksaveasfilename(title="Save DAST profile", defaultextension=".json",
            initialfile="dast_profile.json", filetypes=[("DAST profile","*.json"),("All","*.*")])
        if not path: return
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        self._emit_log(f"[dast] profile saved → {path}  (secrets stripped)")

    def _dast_load_profile(self):
        path = filedialog.askopenfilename(title="Load DAST profile", filetypes=[("DAST profile","*.json"),("All","*.*")])
        if not path: return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as e:
            self._show_error_popup("Load Profile", f"Cannot read file:\n{e}"); return
        _load_map = [
            (self._dast_url_var,"url",str,""), (self._dast_auth_var,"auth_type",str,"none"),
            (self._dast_profile_var,"profile",str,"passive"), (self._dast_pages_var,"max_pages",int,30),
            (self._dast_subs_var,"include_subdomains",bool,False), (self._dast_tls_var,"verify_tls",bool,True),
            (self._dast_relogin_var,"auto_relogin",bool,True), (self._dast_browser_var,"selenium_browser",str,"chrome"),
            (self._dast_headless_var,"selenium_headless",bool,True), (self._dast_selwait_var,"selenium_wait_seconds",int,15),
            (self._dast_exclude_var,"exclude_re",str,""), (self._dast_rps_var,"rate_limit_rps",float,8.0),
            (self._dast_workers_var,"concurrency",int,4), (self._dast_proxy_var,"proxy",str,""),
        ]
        for var, key, cast, dflt in _load_map:
            var.set(cast(data.get(key, dflt)))
        try:  # re-detect so a profile saved elsewhere still resolves to a local browser
            self._refresh_browser_catalog()
            if getattr(self, "_dast_browser_cb", None) is not None:
                self._dast_browser_cb.config(values=[i["name"] for i in self._browser_catalog.values()])
            bkey = self._dast_browser_var.get()
            if bkey in self._browser_catalog:
                self._dast_browser_label_var.set(self._browser_catalog[bkey]["name"])
        except Exception:
            pass
        for k, var in self._dast_cred_vars.items():
            var.set(str(data.get(k,"")))
        self._refresh_dast_creds()
        self._emit_log(f"[dast] profile loaded ← {path}")

    def _setup_dast_field_persistence(self):
        """Wire trace callbacks on all DAST vars so they auto-save on change."""
        delay = [None]
        def _on_change(*_):
            if delay[0] is not None:
                try: self.after_cancel(delay[0])
                except Exception: pass
            delay[0] = self.after(800, self._save_settings)
        for v in [self._dast_url_var, self._dast_auth_var, self._dast_profile_var,
                  self._dast_pages_var, self._dast_subs_var, self._dast_tls_var,
                  self._dast_relogin_var, self._dast_exclude_var, self._dast_rps_var,
                  self._dast_workers_var, self._dast_proxy_var, self._dast_browser_var,
                  self._dast_headless_var, self._dast_selwait_var]:
            try: v.trace_add("write", _on_change)
            except Exception: pass
        for k, v in self._dast_cred_vars.items():
            if k not in self._SECRET_KEYS:
                try: v.trace_add("write", _on_change)
                except Exception: pass

    def _restore_dast_fields(self):
        """Apply cached DAST settings (loaded from file in _load_settings) to the tk vars."""
        saved = getattr(self, "_saved_dast_fields", None)
        if not isinstance(saved, dict): return
        try:
            if saved.get("url"):          self._dast_url_var.set(saved["url"])
            if saved.get("auth"):         self._dast_auth_var.set(saved["auth"])
            if saved.get("profile"):      self._dast_profile_var.set(saved["profile"])
            if "pages"    in saved:       self._dast_pages_var.set(int(saved["pages"]))
            if "subs"     in saved:       self._dast_subs_var.set(bool(saved["subs"]))
            if "tls"      in saved:       self._dast_tls_var.set(bool(saved["tls"]))
            if "relogin"  in saved:       self._dast_relogin_var.set(bool(saved["relogin"]))
            if "exclude"  in saved:       self._dast_exclude_var.set(saved["exclude"])
            if "rps"      in saved:       self._dast_rps_var.set(float(saved["rps"]))
            if "workers"  in saved:       self._dast_workers_var.set(int(saved["workers"]))
            if "proxy"    in saved:       self._dast_proxy_var.set(saved["proxy"])
            if saved.get("browser"):      self._dast_browser_var.set(saved["browser"])
            if "headless" in saved:       self._dast_headless_var.set(bool(saved["headless"]))
            if "selwait"  in saved:       self._dast_selwait_var.set(int(saved["selwait"]))
            for k, val in (saved.get("creds") or {}).items():
                if k in self._dast_cred_vars and k not in self._SECRET_KEYS:
                    self._dast_cred_vars[k].set(str(val))
        except Exception:
            pass

    def _dast_save_condition(self, keys, name, initialfile, note=""):
        data = {k: self._dast_cred_vars[k].get() for k in keys if k in self._dast_cred_vars}
        # Passwords are NEVER written to disk — strip any typed password from the recorded macro too.
        if data.get("selenium_macro"):
            try:
                steps = json.loads(data["selenium_macro"])
                for s in steps:
                    if isinstance(s, dict) and s.get("kind") == "field" and (
                            s.get("role") == "password" or s.get("ftype") == "password"):
                        s["value"] = ""  # re-injected at runtime
                data["selenium_macro"] = json.dumps(steps)
            except Exception:
                pass
        path = filedialog.asksaveasfilename(title=f"Save {name}", defaultextension=".json",
            initialfile=initialfile, filetypes=[(name.capitalize(),"*.json"),("All","*.*")])
        if not path: return
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        self._emit_log(f"[dast] {name} saved → {path}{note}")

    def _dast_load_condition(self, keys, name):
        path = filedialog.askopenfilename(title=f"Load {name}", filetypes=[(name.capitalize(),"*.json"),("All","*.*")])
        if not path: return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as e:
            self._show_error_popup(f"Load {name.title()}", f"Cannot read file:\n{e}"); return
        applied = [k for k in keys if k in data and k in self._dast_cred_vars
                   and (self._dast_cred_vars[k].set(str(data[k])) or True)]
        self._refresh_dast_creds()
        self._emit_log(f"[dast] {name} loaded ← {path}  (fields: {', '.join(applied) or 'none'})")

    def _dast_save_login_condition(self):
        self._dast_save_condition(self._LOGIN_CONDITION_KEYS, "login condition",
                                  "dast_login_condition.json", "  (password value excluded)")

    def _dast_load_login_condition(self):
        self._dast_load_condition(self._LOGIN_CONDITION_KEYS, "login condition")

    def _dast_save_logout_condition(self):
        self._dast_save_condition(self._LOGOUT_CONDITION_KEYS, "logout condition", "dast_logout_condition.json")

    def _dast_load_logout_condition(self):
        self._dast_load_condition(self._LOGOUT_CONDITION_KEYS, "logout condition")

    def _record_in_browser(self, err_title, popup_title, instructions, work, *, w_pct=0.32, h_pct=0.30):
        """Launch browser + a small evasive floating HUD (non-modal; dodges the mouse) for recording."""
        url = (self._dast_cred_vars["selenium_login_url"].get().strip() or self._dast_url_var.get().strip())
        if not url or url == "https://":
            self._show_error_popup(err_title, "Set a Target URL or Login page URL first."); return None
        done = threading.Event(); result: dict = {}
        cancelled = [False]  # declared early so the watchdog below can set it
        # Worker thread never touches Tk; it writes the latest message here and a Tk poller copies it.
        status_box: dict = {"msg": None, "shown": None}
        def _emit_status(msg: str): status_box["msg"] = msg
        driver_ready = threading.Event()
        # nav_done is set by work() right after its first driver.get() completes.
        # The watchdog waits for this before probing window_handles, so Chrome's
        # brief data:, startup page is never mistaken for a closed window.
        nav_done = threading.Event()
        result["_nav_done"] = nav_done

        def runner():
            try:
                drv = _make_driver(self._collect_dast_cfg(), headless=False, log=self._emit_log)
                result["_driver"] = drv; driver_ready.set()
                try:
                    work(drv, url, done, result, _emit_status)
                finally:
                    try: drv.quit()
                    except Exception: pass
            except Exception as e:
                result["error"] = repr(e); driver_ready.set()
            finally:
                nav_done.set()  # unblock watchdog if work() raised before setting it
                done.set()

        t = threading.Thread(target=runner, daemon=True); t.start()

        # ── Browser-closed watchdog ─────────────────────────────────────────
        # `work()` only calls done.set() on its own happy/error paths. If the
        # user closes the actual browser window (instead of using a hotkey or
        # finishing the flow), the Selenium session is left dangling — and
        # depending on the driver/OS, the *next* command Selenium tries to send
        # to it can simply hang with no timeout, which is what made the whole
        # app look like it had stopped responding (wait_window() never returns
        # because done never gets set).
        #
        # Each probe below runs `drv.window_handles` (a cheap call scoped to
        # THIS recording's own WebDriver session — not to "is some window of
        # this browser open", so other unrelated windows of the same browser
        # don't interfere and the *specific* launched instance is what's being
        # checked) inside its own short-lived thread so a hung probe can't
        # itself block the watchdog. Two consecutive failures/timeouts (~5s)
        # are treated as "the window was closed" and cancel the operation.
        watchdog_stop = threading.Event()
        def _watchdog():
            misses = 0
            if not driver_ready.wait(timeout=30):
                return  # browser never came up — runner()'s own error path handles it
            # Wait for the first real driver.get() to complete before probing.
            # Chrome briefly shows a data:, blank page between driver creation
            # and the first navigation; probing window_handles during that window
            # can return an empty list (or raise) and trigger a false-positive
            # "browser closed" cancel. nav_done is set by work() right after its
            # first driver.get() returns, so we start probing only once Chrome
            # has actually opened the target page.
            if not nav_done.wait(timeout=60):
                return  # navigation never happened — runner() will set done
            if done.is_set() or watchdog_stop.is_set():
                return  # recording finished during the nav wait; nothing to watch
            while not (done.is_set() or watchdog_stop.is_set()):
                drv = result.get("_driver")
                if drv is None:
                    return
                probe_done = threading.Event(); probe_ok = {"v": False}
                def _probe(drv=drv):
                    try:
                        _ = drv.window_handles
                        if _:  # empty list = no windows left = closed
                            probe_ok["v"] = True
                    except Exception:
                        probe_ok["v"] = False
                    finally:
                        probe_done.set()
                threading.Thread(target=_probe, daemon=True).start()
                if not probe_done.wait(timeout=3.0) or not probe_ok["v"]:
                    misses += 1
                else:
                    misses = 0
                if misses >= 2:
                    self._emit_log("[record] browser window was closed — cancelling operation.")
                    cancelled[0] = True
                    done.set()
                    try: drv.quit()
                    except Exception: pass
                    return
                if done.wait(timeout=1.5):
                    return

        threading.Thread(target=_watchdog, daemon=True).start()
        HUD_W, HUD_H = 360, 105
        PADDING = 14
        CORNERS = ["ne", "nw", "sw", "se"]
        hud = tk.Toplevel(self)
        hud.overrideredirect(True); hud.attributes("-topmost", True)
        hud.attributes("-alpha", 0.90); hud.resizable(False, False)
        hud._corner_idx = [0]  # starts at NE

        def _place_hud(corner: str):
            sw = hud.winfo_screenwidth(); sh = hud.winfo_screenheight()
            if corner == "ne":   x, y = sw - HUD_W - PADDING, PADDING
            elif corner == "nw": x, y = PADDING, PADDING
            elif corner == "sw": x, y = PADDING, sh - HUD_H - PADDING
            else:                x, y = sw - HUD_W - PADDING, sh - HUD_H - PADDING
            hud.geometry(f"{HUD_W}x{HUD_H}+{x}+{y}")

        def _dodge(event=None):
            idx = (hud._corner_idx[0] + 1) % len(CORNERS)
            hud._corner_idx[0] = idx; _place_hud(CORNERS[idx])

        _place_hud(CORNERS[0])
        outer = tk.Frame(hud, bg=T["accent"], padx=1, pady=1); outer.pack(fill="both", expand=True)
        inner = tk.Frame(outer, bg=T["panel_bg"], padx=10, pady=8); inner.pack(fill="both", expand=True)
        tk.Label(inner, text=popup_title, font=(_FUI, 10, "bold"), bg=T["panel_bg"], fg=T["accent"]).pack(anchor="w")
        status_var = tk.StringVar(value="⏳  Opening browser…")
        tk.Label(inner, textvariable=status_var, font=(_FUI, 9), bg=T["panel_bg"], fg=T["muted"],
                 wraplength=HUD_W - 24).pack(anchor="w", pady=(2, 4))
        hotkey_lbl = tk.Label(inner, text="Ctrl+Shift+F12  →  capture     Ctrl+Shift+F11  →  cancel",
                              font=(_FUI, 8), bg=T["panel_bg"], fg=T["muted"])
        hotkey_lbl.pack(anchor="w")
        for widget in (hud, outer, inner, hotkey_lbl): widget.bind("<Enter>", _dodge, "+")
        ready = [False]
        _hotkey_stop = threading.Event(); _hotkey_cancel = threading.Event()

        # Global hotkey via pynput (works even when browser has focus): Ctrl+Shift+F12 capture, F11 cancel.
        def _pynput_listener():
            try:
                from pynput import keyboard as _kb
                _pressed = set()
                def _on_press(key):
                    _pressed.add(key)
                    ctrl = any(k in _pressed for k in (_kb.Key.ctrl, _kb.Key.ctrl_l, _kb.Key.ctrl_r))
                    shift = any(k in _pressed for k in (_kb.Key.shift, _kb.Key.shift_l, _kb.Key.shift_r))
                    if ctrl and shift:
                        if key == _kb.Key.f12: _hotkey_stop.set()
                        elif key == _kb.Key.f11: _hotkey_cancel.set()
                def _on_release(key): _pressed.discard(key)
                with _kb.Listener(on_press=_on_press, on_release=_on_release) as lst:
                    while not done.is_set():
                        if done.wait(0.2): break
                    lst.stop()
            except Exception as ex:
                self._emit_log(f"[hotkey] pynput unavailable ({ex!r}) — "
                               "press Ctrl+Shift+F12 while the Scanner window is focused")

        threading.Thread(target=_pynput_listener, daemon=True).start()

        def _on_key_tk(event):  # fallback binding when Scanner window has focus
            ctrl = bool(event.state & 0x4); shift = bool(event.state & 0x1)
            if ctrl and shift and event.keysym == "F12": _hotkey_stop.set()
            elif ctrl and shift and event.keysym == "F11": _hotkey_cancel.set()

        _key_bind_id = self.bind("<KeyPress>", _on_key_tk, "+")
        hud.bind("<KeyPress>", _on_key_tk, "+")

        def _poll_hotkeys():
            if _hotkey_cancel.is_set():
                cancelled[0] = True; done.set(); return
            if _hotkey_stop.is_set() and ready[0]:
                done.set(); return
            hud.after(150, _poll_hotkeys)

        hud.after(150, _poll_hotkeys)

        def _poll_ready():
            if driver_ready.is_set():
                if "error" not in result:
                    if status_box.get("msg") is None:  # don't stomp a worker-emitted status
                        status_var.set("✅  Browser open — interact freely")
                    ready[0] = True
                else:
                    status_var.set("❌  Browser failed")
                return
            hud.after(200, _poll_ready)

        hud.after(200, _poll_ready)

        def _poll_status():
            m = status_box.get("msg")
            if m is not None and m != status_box.get("shown"):
                status_var.set(m); status_box["shown"] = m
            if not (done.is_set() or cancelled[0]): hud.after(180, _poll_status)

        hud.after(180, _poll_status)

        def _poll_done():
            if done.is_set() or cancelled[0]:
                try: self.unbind("<KeyPress>", _key_bind_id)
                except Exception: pass
                try: hud.destroy()
                except Exception: pass
                return
            hud.after(300, _poll_done)

        hud.after(300, _poll_done)
        self.wait_window(hud)  # block until recording is done
        t.join(timeout=1.5 if (cancelled[0] or result.get("_cancelled")) else 10)
        if cancelled[0] or result.get("_cancelled") or "error" in result:
            if "error" in result:
                self._show_error_popup(err_title, f"Browser failed:\n{result['error']}")
            return None
        result["_url"] = url
        return result

    def _dast_record_macro(self):
        work = record_macro_work(self._collect_dast_cfg(), emit_log=self._emit_log)  # engine-side factory, no GUI
        result = self._record_in_browser("Record Login Condition", "⏺ Login Condition",
                                         [], work, w_pct=0.32, h_pct=0.30)
        if result is None: return False  # cancelled or error — no palomita
        url = result["_url"]
        try: macro = json.loads(result.get("macro") or "[]")
        except Exception: macro = []
        if not isinstance(macro, list): macro = []
        macro = [s for s in macro if isinstance(s, dict)]
        user_sel, user_val, pass_sel, pass_val, submit_sel = self._analyze_login_macro(macro)
        # A login submitted with Enter (or whose button can't be pinned) is replayed via the form, not a click.
        submit_extra = None
        if not submit_sel:
            sub = next((s for s in macro if s.get("kind") == "submit"), None)
            ent = next((s for s in macro if s.get("kind") == "enter"), None)
            if sub and sub.get("button"): submit_sel = sub["button"]
            elif sub and sub.get("form"): submit_extra = {"submit": sub["form"]}
            elif ent and ent.get("form"): submit_extra = {"submit": ent["form"]}
            elif ent: submit_extra = {"key": "Enter", "selector": ent.get("selector") or pass_sel}
        if user_sel: self._dast_cred_vars["selenium_user_selector"].set(user_sel)
        if user_val: self._dast_cred_vars["selenium_user_value"].set(user_val)
        if pass_sel: self._dast_cred_vars["selenium_pass_selector"].set(pass_sel)
        if pass_val: self._dast_cred_vars["selenium_pass_value"].set(pass_val)  # session-only; stripped from saves
        self._dast_cred_vars["selenium_submit_selector"].set(submit_sel or "")
        if not self._dast_cred_vars["selenium_login_url"].get():
            self._dast_cred_vars["selenium_login_url"].set(url)
        # Extra steps = other meaningful fields/clicks minus user/pass/submit and minus anything logout-like.
        _LOGOUT_RE = _re.compile(
            r"(?i)(logout|log[\s_-]?out|sign[\s_-]?out|signoff|cerrar[\s_-]?sesi[oó]n|salir)")
        extras: list = []
        for s in macro:
            kind = s.get("kind"); sel = s.get("selector")
            if kind == "field" and sel and sel not in (user_sel, pass_sel) \
                    and s.get("role") != "password" and s.get("value"):
                extras.append({"selector": sel, "value": s["value"]})
            elif kind == "click" and sel and sel != submit_sel:
                blob = f"{sel} {s.get('text','')}"
                if _LOGOUT_RE.search(blob): continue  # never replay a logout click
                extras.append({"click": sel})
        if submit_extra: extras.append(submit_extra)
        self._dast_cred_vars["selenium_extra_steps"].set(json.dumps(extras) if extras else "")
        # Save the FULL recording too (literal step-by-step replay), dropping only logout-like clicks.
        literal: list = []
        for s in macro:
            if s.get("kind") == "click":
                blob = f"{s.get('selector','')} {s.get('text','')}"
                if _LOGOUT_RE.search(blob): continue
            literal.append(s)
        self._dast_cred_vars["selenium_macro"].set(json.dumps(literal) if literal else "")
        submit_desc = (submit_sel if submit_sel else "Enter / form submit" if submit_extra else "(not detected)")
        self._emit_log(f"[macro] captured {len(macro)} interactions — "
                       f"user={user_sel!r} pass={pass_sel!r} submit={submit_desc!r}")
        pass_note = ("✔ captured (runtime only)" if pass_val
                     else "(type it in Password value before recording Logout)")
        self._show_info_popup("Login Condition",
            f"Captured {len(macro)} interactions.\n\n"
            f"Username selector:  {user_sel or '(not detected)'}\n"
            f"Password selector:  {pass_sel or '(not detected)'}\n"
            f"Password value:     {pass_note}\n"
            f"Submit:             {submit_desc}\n\n"
            "Submit is the action that sends the login form — a button click, "
            "or an Enter / form submit when there's no button.\n"
            "The password is held only in this session and is wiped when you "
            "close the program; it's never written to any saved file.")
        self._refresh_dast_creds()
        return True  # signal success to _macro_popup → palomita

    @staticmethod
    def _analyze_login_macro(macro: list) -> tuple:
        """Delegate to dast_api.analyze_login_macro (pure-logic, no GUI)."""
        return analyze_login_macro(macro)

    def _dast_record_logout(self):
        """Replay the login macro to reach the logged-in state, then capture the logged-out state."""
        cfg = self._collect_dast_cfg()
        pass_sel = cfg.selenium_pass_selector
        pass_val = cfg.selenium_pass_value
        password_missing = bool(pass_sel and not pass_val)
        if password_missing:  # non-blocking heads-up; browser opens right after for manual login + capture
            self._show_info_popup("Logout Condition — manual login needed",
                "Your login was recorded, but the password wasn't saved "
                "(passwords are never written to disk).\n\n"
                "The browser will open at the login page. Log in by hand, go to "
                "the logged-OUT page, then press Ctrl+Shift+F12 to capture.\n\n"
                "Tip: type your password into the “Password value” field of the "
                "credentials section first and the login will replay itself "
                "automatically next time.")
        work = record_logout_work(cfg, emit_log=self._emit_log)  # engine-side factory, no GUI
        result = self._record_in_browser("Record Logout Condition", "⏺ Logout Condition",
                                         [], work, w_pct=0.34, h_pct=0.32)
        if result is None: return False  # cancelled or browser error — no palomita
        final_url = result.get("final_url","").strip()
        logout_macro = result.get("logout_macro", [])
        logout_hrefs = result.get("logout_href_candidates", [])
        last_click = result.get("last_logout_click", {})
        snapshot = result.get("snapshot", {})
        hints = snapshot.get("hints", [])
        page_title = snapshot.get("title","")
        # Ensure the last click is in the macro so replay has something to execute (SPA buttons w/o href/kw).
        if logout_macro and last_click and last_click.get("selector"):
            last_sel = last_click["selector"]
            macro_sels = [s.get("selector","") for s in logout_macro if s.get("kind") == "click"]
            if last_sel not in macro_sels:
                logout_macro = list(logout_macro) + [{
                    "kind": "click", "selector": last_click.get("selector", ""),
                    "fallback_selectors": last_click.get("fallback_selectors", []),
                    "href": last_click.get("href", ""), "text": last_click.get("text", ""),
                    "el_id": last_click.get("el_id", ""), "el_cls": last_click.get("el_cls", ""),
                    "data_action": last_click.get("data_action", ""),
                }]
                self._emit_log("[logout-rec] appended last click to macro (no kw match)")
        elif not logout_macro and last_click and last_click.get("selector"):
            logout_macro = [{
                "kind": "click", "selector": last_click.get("selector", ""),
                "fallback_selectors": last_click.get("fallback_selectors", []),
                "href": last_click.get("href", ""), "text": last_click.get("text", ""),
                "el_id": last_click.get("el_id", ""), "el_cls": last_click.get("el_cls", ""),
                "data_action": last_click.get("data_action", ""),
            }]
            self._emit_log("[logout-rec] built 1-step macro from last click (no macro recorded)")
        _LOGOUT_KW = ("logout","log-out","signout","sign-out","cerrar","salir")
        def _path_of(u):
            try:
                from urllib.parse import urlparse as _up2
                p = _up2(u if "://" in u else "https://x" + u).path.rstrip("/") or "/"
                return p if p != "/" else None
            except Exception:
                return None
        proposed_re = ""; best_path = None
        for h in logout_hrefs:
            p = _path_of(h)
            if p and any(k in p.lower() for k in _LOGOUT_KW): best_path = p; break
        if not best_path:
            for h in logout_hrefs:
                p = _path_of(h)
                if p: best_path = p; break
        if not best_path and final_url: best_path = _path_of(final_url)
        if not best_path and last_click.get("href"): best_path = _path_of(last_click["href"])
        if best_path: proposed_re = _re.escape(best_path) + r"(\?|$)"
        self._emit_log(f"[logout-rec] proposed_re={proposed_re!r} from path={best_path!r}")
        confirm = self._create_popup("Logout condition — review & confirm")
        self._popup_hdr(confirm, "Logout Condition", subtitle="review captured signals", icon="🔓")
        # Footer pinned to the bottom FIRST so Apply/Cancel can never be pushed off-screen.
        _cb: dict = {"apply": lambda: None}
        foot = tk.Frame(confirm, bg=T["panel_bg"], padx=28, pady=12); foot.pack(side="bottom", fill="x")
        self._btn(foot, "Apply", lambda: _cb["apply"](), "accent").pack(side="right", padx=(6, 0))
        self._btn(foot, "Cancel", lambda: confirm.close(), "flat").pack(side="right", padx=(6, 0))
        tk.Frame(confirm, bg=T["border"], height=1).pack(side="bottom", fill="x")
        canvas = tk.Canvas(confirm, bg=T["bg"], highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(confirm, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y"); canvas.pack(side="left", fill="both", expand=True)
        cbody = tk.Frame(canvas, bg=T["bg"], padx=28, pady=14)
        cwin = canvas.create_window((0, 0), window=cbody, anchor="nw")
        def _sync_scroll(_e=None): canvas.configure(scrollregion=canvas.bbox("all"))
        def _sync_width(e): canvas.itemconfigure(cwin, width=e.width)
        cbody.bind("<Configure>", _sync_scroll); canvas.bind("<Configure>", _sync_width)
        def _wheel(e):
            try: canvas.yview_scroll(-1 * int(e.delta / 120), "units")
            except Exception: pass
        canvas.bind("<MouseWheel>", _wheel); cbody.bind("<MouseWheel>", _wheel)
        cbody.columnconfigure(1, weight=1)
        row_idx = [0]
        def _row(widget_or_text, *, col=0, span=1, sticky="w", advance=True, **gkw):
            w = widget_or_text
            if isinstance(w, str):
                w = self._lbl(cbody, w, size=9, fg=T["muted"], wraplength=430, anchor="w"); span = 2
            w.grid(row=row_idx[0], column=col, columnspan=span, sticky=sticky, **gkw)
            if advance: row_idx[0] += 1
            return w
        def _field(label, value_var):
            _row(self._lbl(cbody, label, size=10, fg=T["muted"], anchor="e"),
                 sticky="e", advance=False, padx=(0, 8), pady=3)
            e = ttk.Entry(cbody, textvariable=value_var); _row(e, col=1, sticky="ew", pady=3); return e
        _row(self._lbl(cbody, "Captured URL", size=10, fg=T["muted"], anchor="e"),
             sticky="e", advance=False, padx=(0, 8), pady=3)
        _row(self._lbl(cbody, final_url or "(none)", size=10, fg=T["text"], anchor="w", wraplength=420), col=1)
        re_var = tk.StringVar(value=proposed_re)
        _row(self._lbl(cbody, "Logout URL regex", size=10, fg=T["muted"], anchor="e"),
             sticky="e", advance=False, padx=(0, 8), pady=3)
        _re_entry = ttk.Entry(cbody, textvariable=re_var); _row(_re_entry, col=1, sticky="ew", pady=3)
        regex_hint = (
            "URLs matching this regex are SKIPPED so the scanner never logs itself out.\n"
            + ("⚠  Captured URL was root (/). Enter the path the app redirects to after "
               "logout (e.g. /login or /signin). Leave blank if the app stays at / — "
               "use Logged-in selector/text below for session detection instead."
               if not proposed_re else
               "Regex must match a specific path (e.g. /login or /logout). "
               "Avoid patterns that match / — they are too broad and will be rejected."))
        _row(regex_hint)
        _row(tk.Frame(cbody, bg=T["border"], height=1), span=2, sticky="ew", pady=10)
        _row(self._lbl(cbody, "SESSION DETECTION", size=9, fg=T["muted"], bold=True, anchor="w"), span=2)
        _row("Optionally tell the scanner what a LOGGED-IN page looks like "
             "so it can detect session loss mid-scan and re-authenticate.")
        sel_var = tk.StringVar(value=self._dast_cred_vars["login_success_selector"].get())
        _field("Logged-in selector", sel_var)
        _row("CSS selector present ONLY when logged in (e.g. #user-avatar).")
        txt_var = tk.StringVar(value=self._dast_cred_vars["login_success_text"].get())
        _field("Logged-in text", txt_var)
        _row("Text ONLY visible when logged in (e.g. 'My Account').")
        # Recorded logout action + protection summary — answers "how does it avoid logging itself out?".
        if logout_macro:
            _row(tk.Frame(cbody, bg=T["border"], height=1), span=2, sticky="ew", pady=(10, 4))
            _row(self._lbl(cbody, "LOGOUT ACTION RECORDED", size=9, fg=T["muted"], bold=True, anchor="w"), span=2)
            click_steps = [s for s in logout_macro if s.get("kind") == "click"]
            _row(f"✓ {len(logout_macro)} step(s) recorded "
                 f"({len(click_steps)} click(s)). The last click is treated as the logout action.")
            if last_click and last_click.get("selector"):
                lc_text = (last_click.get("text") or "").strip()
                lc_sel = (last_click.get("selector") or "").strip()
                lc_id = (last_click.get("el_id") or "").strip()
                lc_href = (last_click.get("href") or "").strip()
                lc_data = (last_click.get("data_action") or "").strip()
                if lc_text: _row(f"  · Button text: “{lc_text}”")
                if lc_sel: _row(f"  · CSS selector: {lc_sel[:70]}")
                if lc_id: _row(f"  · Element id: {lc_id}")
                if lc_data: _row(f"  · data-action: {lc_data}")
                if lc_href and lc_href not in ("#", "javascript:void(0)", "javascript:;"):
                    _row(f"  · Navigates to: {lc_href[:70]}")
                else:
                    _row("  · No navigation URL (SPA button) — protection is "
                         "by element identity, not URL.")
            _row(tk.Frame(cbody, bg=T["border"], height=1), span=2, sticky="ew", pady=(8, 4))
            _row(self._lbl(cbody, "HOW THE SCANNER AVOIDS LOGGING OUT", size=9, fg=T["muted"], bold=True, anchor="w"), span=2)
            if proposed_re:
                _row("✓ Logout URL pre-filled — scanner skips URLs matching it during crawl.")
            else:
                _row("✓ No distinct logout URL. Scanner skips links/forms whose text or attributes match logout keywords (logout, signout, Salir…) and never clicks JS-only buttons during crawl.")
            _row("✓ Default pattern also blocks /logout, /signout, /sign-out, /log-out, /api/logout.")
        if hints or page_title or snapshot.get("has_password_field") or snapshot.get("has_login_form"):
            _row(tk.Frame(cbody, bg=T["border"], height=1), span=2, sticky="ew", pady=(10, 4))
            _row("Signals detected on logout page (for reference):")
            strong = []
            if snapshot.get("has_password_field"): strong.append("password field present (typical of a login page)")
            if snapshot.get("has_login_form"): strong.append("login form present")
            for s in strong: _row(f"  ✓ {s}")
            # Collapse whitespace defensively — old captures could embed a whole <form> innerText.
            clean_hints = []
            for h in hints:
                h = _re.sub(r"\s+", " ", str(h)).strip()[:80]
                if h and h not in clean_hints: clean_hints.append(h)
            for h in ([f"Page title: {page_title}"] if page_title else []) + clean_hints[:8]:
                _row(f"  · {h}")
        elif not final_url:
            _row(tk.Frame(cbody, bg=T["border"], height=1), span=2, sticky="ew", pady=(10, 4))
            _row("⚠️  No page data was captured. Make sure you pressed "
                 "Ctrl+Shift+F12 *while on the logged-out page* (the browser "
                 "must still be open). You can type the Logout URL regex above "
                 "by hand and Apply.")
        applied: list[bool] = [False]
        def _apply():
            re_val = re_var.get().strip(); sel_val = sel_var.get().strip(); txt_val = txt_var.get().strip()
            if re_val: self._dast_cred_vars["logout_url_re"].set(re_val)
            if sel_val: self._dast_cred_vars["login_success_selector"].set(sel_val)
            if txt_val: self._dast_cred_vars["login_success_text"].set(txt_val)
            if logout_macro:
                self._dast_cred_vars["selenium_logout_macro"].set(json.dumps(logout_macro))
                self._emit_log(f"[logout-rec] logout macro saved ({len(logout_macro)} steps)")
            else:
                self._emit_log("[logout-rec] WARNING: 0 logout steps recorded — "
                               "open user menu and click Log Out while recorder is running")
            applied[0] = True
            self._emit_log(f"[logout-rec] applied — regex={re_val!r} selector={sel_val!r} text={txt_val!r}")
            self._refresh_dast_creds(); confirm.close()
        _cb["apply"] = _apply  # footer Apply button → this handler
        def _bind_wheel_rec(w):  # wheel must work over labels/entries too, not just the canvas
            try: w.bind("<MouseWheel>", _wheel)
            except Exception: pass
            for child in w.winfo_children(): _bind_wheel_rec(child)
        _bind_wheel_rec(cbody)
        self.wait_window(confirm._win)
        if not applied[0]:
            self._emit_log("[logout-rec] cancelled — no changes applied"); return False
        return True  # signal success to _macro_popup → palomita

    def _dast_test_logout(self):
        """Replay the login macro, navigate to the logout URL, then close the browser — end-to-end check."""
        cfg = self._collect_dast_cfg()
        login_url = cfg.selenium_login_url.strip() or self._dast_url_var.get().strip()
        if not login_url or login_url == "https://":
            self._show_error_popup("Test Logout", "Set a Target URL or Login page URL before running the test.")
            return
        work = test_logout_work(cfg, emit_log=self._emit_log)  # engine-side factory drives done.set() itself
        result = self._record_in_browser("Test Logout Condition", "🧪 Test Logout",
                                         [], work, w_pct=0.34, h_pct=0.28)
        if result is None:
            self._emit_log("[test-logout] cancelled or browser error"); return
        reached = result.get("logout_url_reached", "")
        logout_replayed = result.get("logout_replayed", False)
        if result.get("test_done"):
            if logout_replayed:
                url_line = (f"\n\nFinal URL:\n{reached}" if reached else "")  # SPA: URL may not change
                self._show_info_popup("Test Logout — ✅ Success",
                    f"Login and logout completed successfully.{url_line}")
            else:
                self._show_info_popup("Test Logout — ⚠️ Incomplete",
                    "Login replayed but logout could not be completed.\n\n"
                    "Re-record the Logout Condition:\n"
                    "open user menu → click Log Out → Ctrl+Shift+F12.")
        else:
            self._emit_log("[test-logout] test did not complete normally")

    def _refresh_browser_catalog(self) -> list[str]:
        """Detect installed browsers, refresh label↔key maps, return friendly labels for the combobox."""
        catalog = {}
        try:
            catalog = detect_browsers() or {}
        except Exception:
            try:
                from dast_api import detect_browsers as _db
                catalog = _db() or {}
            except Exception:
                catalog = {}
        if not catalog:  # never leave the dropdown empty
            catalog = {"chrome": {"name": "Google Chrome", "binary": "", "engine": "chromium"}}
        self._browser_catalog = catalog
        self._browser_label_key = {info["name"]: key for key, info in catalog.items()}
        labels = [info["name"] for info in catalog.values()]
        cur_key = self._dast_browser_var.get()
        if cur_key not in catalog:
            cur_key = next(iter(catalog)); self._dast_browser_var.set(cur_key)
        self._dast_browser_label_var.set(catalog[cur_key]["name"])
        return labels
