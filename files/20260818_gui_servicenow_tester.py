#!/usr/bin/env python3

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import test_servicenow_ticket as core


class ServiceNowTesterGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ServiceNow Ticket Tester — Plataformas DEV")
        self.geometry("960x760")
        self.minsize(860, 640)

        self.msg_queue: queue.Queue = queue.Queue()
        self.scenario_vars: dict[str, tk.BooleanVar] = {}
        self.ticket_rows: dict[str, dict] = {}
        self.running = False

        self._build_widgets()
        self._load_saved_credentials()
        self._maximize_window()
        self.after(100, self._poll_queue)
        self._log(f"Log CSV: {core.LOG_FILE}")

    def _build_widgets(self):
        pad = {"padx": 8, "pady": 6}

        creds = ttk.LabelFrame(self, text="Credenciales")
        creds.pack(fill="x", **pad)

        ttk.Label(creds, text="Usuario:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        self.user_entry = ttk.Entry(creds, width=22)
        self.user_entry.grid(row=0, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(creds, text="Password:").grid(row=0, column=2, sticky="e", padx=4, pady=4)
        self.pass_entry = ttk.Entry(creds, width=22, show="•")
        self.pass_entry.grid(row=0, column=3, sticky="w", padx=4, pady=4)

        ttk.Label(creds, text="Token (opcional):").grid(row=0, column=4, sticky="e", padx=4, pady=4)
        self.token_entry = ttk.Entry(creds, width=20, show="•")
        self.token_entry.grid(row=0, column=5, sticky="w", padx=4, pady=4)

        self.remember_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(creds, text="Recordar en este equipo (texto plano — solo DEV)",
                         variable=self.remember_var).grid(row=1, column=0, columnspan=4, sticky="w", padx=4, pady=4)
        ttk.Button(creds, text="Olvidar credenciales guardadas", command=self._on_forget).grid(
            row=1, column=4, columnspan=2, sticky="w", padx=4, pady=4)

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, **pad)

        run_tab = ttk.Frame(notebook)
        tickets_tab = ttk.Frame(notebook)
        notebook.add(run_tab, text="Ejecutar pruebas")
        notebook.add(tickets_tab, text="Tickets existentes")

        self._build_run_tab(run_tab, pad)
        self._build_tickets_tab(tickets_tab, pad)

        log_frame = ttk.LabelFrame(self, text="Log")
        log_frame.pack(fill="both", expand=False, **pad)
        self.log_text = tk.Text(log_frame, wrap="word", state="disabled", height=10)
        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _build_run_tab(self, parent, pad):
        scen_frame = ttk.LabelFrame(parent, text="Servicios a incluir en el ticket (se crea UNO solo con todo lo marcado)")
        scen_frame.pack(fill="x", **pad)
        for i, name in enumerate(core.SERVICES.keys()):
            var = tk.BooleanVar(value=True)
            self.scenario_vars[name] = var
            ttk.Checkbutton(scen_frame, text=name, variable=var).grid(
                row=0, column=i, sticky="w", padx=10, pady=6)

        opts = ttk.LabelFrame(parent, text="Opciones")
        opts.pack(fill="x", **pad)

        ttk.Label(opts, text="Ambiente (opcional, ej. Producción):").grid(
            row=0, column=0, sticky="e", padx=4, pady=4)
        self.ambiente_entry = ttk.Entry(opts, width=20)
        self.ambiente_entry.grid(row=0, column=1, sticky="w", padx=4, pady=4)

        self.dry_run_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Dry run (no envía nada)", variable=self.dry_run_var).grid(
            row=0, column=2, sticky="w", padx=10, pady=4)

        self.cleanup_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Cancelar tickets de prueba al terminar",
                         variable=self.cleanup_var).grid(row=0, column=3, sticky="w", padx=10, pady=4)

        ttk.Label(opts, text="Nombre de la aplicación:").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        self.app_name_entry = ttk.Entry(opts, width=30)
        self.app_name_entry.insert(0, core.DEFAULT_APP_NAME)
        self.app_name_entry.grid(row=1, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(opts, text="Descripción / justificación:").grid(row=1, column=2, sticky="e", padx=4, pady=4)
        self.descripcion_entry = ttk.Entry(opts, width=45)
        self.descripcion_entry.insert(0, core.DEFAULT_DESCRIPTION)
        self.descripcion_entry.grid(row=1, column=3, sticky="w", padx=4, pady=4)

        ttk.Label(opts, text="Nombre del solicitante:").grid(row=2, column=0, sticky="e", padx=4, pady=4)
        self.solicitante_nombre_entry = ttk.Entry(opts, width=30)
        self.solicitante_nombre_entry.insert(0, core.BASE_FIELDS.get("nombre_del_solicitante", ""))
        self.solicitante_nombre_entry.grid(row=2, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(opts, text="Correo del solicitante:").grid(row=2, column=2, sticky="e", padx=4, pady=4)
        self.solicitante_correo_entry = ttk.Entry(opts, width=30)
        self.solicitante_correo_entry.insert(0, core.BASE_FIELDS.get("correo_del_solicitante", ""))
        self.solicitante_correo_entry.grid(row=2, column=3, sticky="w", padx=4, pady=4)

        ttk.Label(opts, text="ID (usuario) del solicitante:").grid(row=3, column=0, sticky="e", padx=4, pady=4)
        self.solicitante_id_entry = ttk.Entry(opts, width=20)
        self.solicitante_id_entry.insert(0, core.BASE_FIELDS.get("id_del_solicitante", ""))
        self.solicitante_id_entry.grid(row=3, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(opts, text="Overrides (una var=valor por línea):").grid(row=4, column=0, sticky="ne", padx=4, pady=4)
        self.overrides_text = tk.Text(opts, width=60, height=3)
        self.overrides_text.grid(row=4, column=1, columnspan=3, sticky="w", padx=4, pady=4)

        run_frame = ttk.Frame(parent)
        run_frame.pack(fill="x", **pad)
        self.run_button = ttk.Button(run_frame, text="Ejecutar pruebas", command=self._on_run)
        self.run_button.pack(side="left")
        self.inspect_button = ttk.Button(run_frame, text="Inspeccionar variables obligatorias",
                                          command=self._on_inspect)
        self.inspect_button.pack(side="left", padx=8)

        ttk.Label(run_frame, text="Campo:").pack(side="left", padx=(12, 2))
        self.inspect_field_entry = ttk.Entry(run_frame, width=20)
        self.inspect_field_entry.pack(side="left")
        self.inspect_field_button = ttk.Button(run_frame, text="Detalle de campo",
                                                command=self._on_inspect_field)
        self.inspect_field_button.pack(side="left", padx=4)

        self.status_label = ttk.Label(run_frame, text="Listo")
        self.status_label.pack(side="left", padx=12)

        table_frame = ttk.LabelFrame(parent, text="Resultados")
        table_frame.pack(fill="both", expand=False, **pad)
        columns = ("scenario", "status", "request_number", "cleanup_status")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=6)
        headings = {"scenario": "Servicios incluidos", "status": "Status", "request_number": "Request #",
                    "cleanup_status": "Limpieza"}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=220 if col == "scenario" else (180 if col == "request_number" else 140), anchor="w")
        self.tree.pack(fill="x")
        self.tree.bind("<Control-c>", self._on_copy_request_number)
        self.tree.bind("<Control-C>", self._on_copy_request_number)

        ttk.Label(parent, foreground="#555",
                  text="Selecciona una fila (o varias con Ctrl+clic) y presiona Ctrl+C para copiar el Request #.").pack(
            fill="x", padx=8)

    def _build_tickets_tab(self, parent, pad):
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill="x", **pad)

        ttk.Label(toolbar, text="Mostrar últimos:").pack(side="left")
        self.ticket_limit_entry = ttk.Entry(toolbar, width=5)
        self.ticket_limit_entry.insert(0, "25")
        self.ticket_limit_entry.pack(side="left", padx=4)

        self.refresh_button = ttk.Button(toolbar, text="Actualizar lista", command=self._on_refresh_tickets)
        self.refresh_button.pack(side="left", padx=8)
        self.select_all_button = ttk.Button(toolbar, text="Seleccionar todos", command=self._on_select_all_tickets)
        self.select_all_button.pack(side="left", padx=4)
        self.cancel_selected_button = ttk.Button(toolbar, text="Cancelar seleccionados",
                                                  command=self._on_cancel_selected_tickets)
        self.cancel_selected_button.pack(side="left", padx=4)
        self.audit_selected_button = ttk.Button(toolbar, text="Auditar seleccionado",
                                                 command=self._on_audit_selected_ticket)
        self.audit_selected_button.pack(side="left", padx=4)

        hint = ttk.Label(parent, foreground="#555",
                          text="Ctrl+clic / Shift+clic para seleccionar varios (individual o en lote). "
                               "'Auditar seleccionado' muestra en el Log quién/qué cambió el estado del ticket "
                               "(útil para saber si lo cerró este programa o un flujo de ServiceNow).")
        hint.pack(fill="x", padx=8)

        table_frame = ttk.Frame(parent)
        table_frame.pack(fill="both", expand=True, **pad)
        columns = ("ritm_number", "state", "created", "short_description")
        self.tickets_tree = ttk.Treeview(table_frame, columns=columns, show="headings",
                                          selectmode="extended", height=16)
        headings = {"ritm_number": "RITM", "state": "Estado", "created": "Creado",
                    "short_description": "Aplicación / Descripción"}
        widths = {"ritm_number": 120, "state": 160, "created": 150, "short_description": 380}
        for col in columns:
            self.tickets_tree.heading(col, text=headings[col])
            self.tickets_tree.column(col, width=widths[col], anchor="w")
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tickets_tree.yview)
        self.tickets_tree.configure(yscrollcommand=vsb.set)
        self.tickets_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

    def _load_saved_credentials(self):
        creds = core.load_saved_credentials()
        if not creds:
            return
        if creds.get("user"):
            self.user_entry.insert(0, creds["user"])
        if creds.get("password"):
            self.pass_entry.insert(0, creds["password"])
        if creds.get("token"):
            self.token_entry.insert(0, creds["token"])
        self.remember_var.set(True)

    def _maybe_save_credentials(self):
        if self.remember_var.get():
            core.save_credentials(
                user=self.user_entry.get().strip(),
                password=self.pass_entry.get(),
                token=self.token_entry.get().strip(),
            )

    def _on_forget(self):
        core.clear_saved_credentials()
        self.remember_var.set(False)
        self._log("Credenciales guardadas eliminadas.")

    def _get_auth(self):
        token = self.token_entry.get().strip()
        user = self.user_entry.get().strip()
        password = self.pass_entry.get()
        if token:
            return None, {"Authorization": f"Bearer {token}"}
        return (user, password), {}

    def _has_credentials(self) -> bool:
        return bool(self.token_entry.get().strip()) or bool(self.user_entry.get().strip() and self.pass_entry.get())

    def _log(self, message: str):
        self.msg_queue.put(("log", message))

    def _set_status(self, text: str):
        self.status_label.configure(text=text)
        self._log(f"[status] {text}")

    def _set_buttons_state(self, state: str):
        for btn in (self.run_button, self.inspect_button, self.inspect_field_button,
                    self.refresh_button, self.select_all_button, self.cancel_selected_button,
                    self.audit_selected_button):
            btn.configure(state=state)

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                if kind == "log":
                    self.log_text.configure(state="normal")
                    self.log_text.insert("end", payload + "\n")
                    self.log_text.see("end")
                    self.log_text.configure(state="disabled")
                elif kind == "row":
                    self.tree.insert("", "end", values=(
                        payload["scenario"], payload["status"],
                        payload.get("request_number", ""), payload.get("cleanup_status", "…")))
                elif kind == "row_update":
                    for item in self.tree.get_children():
                        vals = list(self.tree.item(item, "values"))
                        if vals[0] == payload[0]:
                            vals[3] = payload[1]
                            self.tree.item(item, values=vals)
                elif kind == "tickets_loaded":
                    self.tickets_tree.delete(*self.tickets_tree.get_children())
                    self.ticket_rows.clear()
                    for ticket in payload:
                        item_id = self.tickets_tree.insert("", "end", values=(
                            ticket["ritm_number"], ticket["state"], ticket["created"],
                            ticket["short_description"]))
                        self.ticket_rows[item_id] = ticket
                elif kind == "ticket_state_update":
                    item_id, new_state = payload
                    if self.tickets_tree.exists(item_id):
                        vals = list(self.tickets_tree.item(item_id, "values"))
                        vals[1] = new_state
                        self.tickets_tree.item(item_id, values=vals)
                elif kind == "done":
                    self.running = False
                    self._set_buttons_state("normal")
                    self._set_status("Listo")
                elif kind == "error":
                    messagebox.showerror("Error", payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _on_run(self):
        if self.running:
            return

        selected = [name for name, var in self.scenario_vars.items() if var.get()]
        if not selected:
            messagebox.showwarning("Sin servicios", "Selecciona al menos un servicio a incluir en el ticket.")
            return

        dry_run = self.dry_run_var.get()
        if not dry_run and not self._has_credentials():
            messagebox.showwarning("Credenciales", "Ingresa usuario+password o un token.")
            return

        self._maybe_save_credentials()

        self.tree.delete(*self.tree.get_children())
        self._clear_log()

        self.running = True
        self._set_buttons_state("disabled")
        self._set_status("Ejecutando…")

        ambiente = self.ambiente_entry.get().strip() or None
        app_name = self.app_name_entry.get().strip() or None
        descripcion = self.descripcion_entry.get().strip() or None
        solicitante_nombre = self.solicitante_nombre_entry.get().strip() or None
        solicitante_correo = self.solicitante_correo_entry.get().strip() or None
        solicitante_id = self.solicitante_id_entry.get().strip() or None
        cleanup = self.cleanup_var.get()
        auth, extra_headers = self._get_auth()

        overrides = {}
        for line in self.overrides_text.get("1.0", "end").splitlines():
            line = line.strip()
            if not line:
                continue
            if "=" not in line:
                self._log(f"Ignorando override mal formado (usa var=valor): {line}")
                continue
            k, v = line.split("=", 1)
            overrides[k.strip()] = v.strip()

        thread = threading.Thread(
            target=self._run_worker,
            args=(selected, auth, extra_headers, ambiente, app_name, descripcion,
                  solicitante_nombre, solicitante_correo, solicitante_id, overrides, dry_run, cleanup),
            daemon=True,
        )
        thread.start()

    def _run_worker(self, selected, auth, extra_headers, ambiente, app_name, descripcion,
                     solicitante_nombre, solicitante_correo, solicitante_id, overrides, dry_run, cleanup):
        label = "+".join(selected)
        self._log(f"[config] Limpieza automática (cancelar al terminar): "
                   f"{'ACTIVADA' if cleanup else 'DESACTIVADA'}")
        payload = core.build_payload(selected, ambiente=ambiente, app_name=app_name,
                                      descripcion=descripcion, solicitante_id=solicitante_id,
                                      solicitante_nombre=solicitante_nombre,
                                      solicitante_correo=solicitante_correo, overrides=overrides)
        row = core.send_request(label, payload, auth, extra_headers, dry_run, log=self._log)
        results = [row]
        self.msg_queue.put(("row", row))

        if dry_run:
            self._log("\n(dry-run: nada se envió ni se guardó en el log)")
            self.msg_queue.put(("done", None))
            return

        if cleanup:
            self._log("\nLimpiando tickets de prueba...")
            core.cleanup_results(results, auth, extra_headers, log=self._log)
            for row in results:
                self.msg_queue.put(("row_update", (row["scenario"], row.get("cleanup_status", ""))))
        else:
            for row in results:
                row["cleanup_status"] = "omitido"
                row["cleanup_error"] = ""
                self.msg_queue.put(("row_update", (row["scenario"], "omitido")))

        try:
            core.log_results(results)
            self._log(f"Resultados agregados a {core.LOG_FILE}")
        except OSError as exc:
            self._log(f"No se pudo escribir el log CSV: {exc}")

        self.msg_queue.put(("done", None))

    def _on_inspect(self):
        if self.running:
            return
        if not self._has_credentials():
            messagebox.showwarning("Credenciales", "Ingresa usuario+password o un token.")
            return

        self._maybe_save_credentials()
        self.running = True
        self._set_buttons_state("disabled")
        self._set_status("Consultando variables…")
        auth, extra_headers = self._get_auth()

        def worker():
            self._log(f"--- Variables obligatorias configuradas en el catalog item ({core.SYS_ID}) ---")
            core.list_variables(auth, extra_headers, mandatory_only=True, log=self._log)
            self.msg_queue.put(("done", None))

        threading.Thread(target=worker, daemon=True).start()

    def _on_inspect_field(self):
        if self.running:
            return
        name = self.inspect_field_entry.get().strip()
        if not name:
            messagebox.showwarning("Campo", "Escribe el nombre de la variable a consultar.")
            return
        if not self._has_credentials():
            messagebox.showwarning("Credenciales", "Ingresa usuario+password o un token.")
            return

        self._maybe_save_credentials()
        self.running = True
        self._set_buttons_state("disabled")
        self._set_status(f"Consultando '{name}'…")
        auth, extra_headers = self._get_auth()

        def worker():
            core.get_variable_detail(auth, extra_headers, name, log=self._log)
            self.msg_queue.put(("done", None))

        threading.Thread(target=worker, daemon=True).start()

    def _on_refresh_tickets(self):
        if self.running:
            return
        if not self._has_credentials():
            messagebox.showwarning("Credenciales", "Ingresa usuario+password o un token.")
            return

        try:
            limit = int(self.ticket_limit_entry.get().strip() or "25")
        except ValueError:
            limit = 25

        self._maybe_save_credentials()
        self.running = True
        self._set_buttons_state("disabled")
        self._set_status("Consultando tickets…")
        auth, extra_headers = self._get_auth()

        def worker():
            tickets = core.list_recent_tickets(auth, extra_headers, limit=limit, log=self._log)
            self.msg_queue.put(("tickets_loaded", tickets))
            self.msg_queue.put(("done", None))

        threading.Thread(target=worker, daemon=True).start()

    def _on_select_all_tickets(self):
        self.tickets_tree.selection_set(self.tickets_tree.get_children())

    def _on_cancel_selected_tickets(self):
        if self.running:
            return
        selected = self.tickets_tree.selection()
        if not selected:
            messagebox.showwarning("Sin selección", "Selecciona al menos un ticket (Ctrl+clic para varios).")
            return
        if not self._has_credentials():
            messagebox.showwarning("Credenciales", "Ingresa usuario+password o un token.")
            return
        if not messagebox.askyesno("Confirmar", f"¿Cancelar {len(selected)} ticket(s) seleccionados? Esta acción no se puede deshacer desde aquí."):
            return

        to_cancel = []
        for item_id in selected:
            ticket = self.ticket_rows.get(item_id)
            if ticket and ticket.get("request_sys_id"):
                to_cancel.append((item_id, ticket))
            elif ticket:
                self._log(f"  {ticket.get('ritm_number')}: sin sys_id de REQ, se omite.")

        self.running = True
        self._set_buttons_state("disabled")
        self._set_status("Cancelando…")
        auth, extra_headers = self._get_auth()

        def worker():
            seen_req_sys_ids = set()
            for item_id, ticket in to_cancel:
                req_sys_id = ticket["request_sys_id"]
                if req_sys_id in seen_req_sys_ids:
                    continue
                seen_req_sys_ids.add(req_sys_id)
                result = core.cancel_request(req_sys_id, auth, extra_headers, log=self._log)
                new_state = "cancelado" if result["cancelled"] else f"error: {result['cleanup_error'][:40]}"
                self.msg_queue.put(("ticket_state_update", (item_id, new_state)))
            self.msg_queue.put(("done", None))

        threading.Thread(target=worker, daemon=True).start()

    def _on_audit_selected_ticket(self):
        if self.running:
            return
        selected = self.tickets_tree.selection()
        if not selected:
            messagebox.showwarning("Sin selección", "Selecciona un ticket para auditar.")
            return
        if not self._has_credentials():
            messagebox.showwarning("Credenciales", "Ingresa usuario+password o un token.")
            return

        item_id = selected[0]
        ticket = self.ticket_rows.get(item_id)
        if not ticket:
            return

        self._maybe_save_credentials()
        self.running = True
        self._set_buttons_state("disabled")
        self._set_status("Auditando…")
        auth, extra_headers = self._get_auth()

        def worker():
            if ticket.get("ritm_sys_id"):
                core.get_audit_history("sc_req_item", ticket["ritm_sys_id"], auth, extra_headers, log=self._log)
            if ticket.get("request_sys_id"):
                self._log("")
                core.get_audit_history("sc_request", ticket["request_sys_id"], auth, extra_headers, log=self._log)
            self.msg_queue.put(("done", None))

        threading.Thread(target=worker, daemon=True).start()

    def _on_copy_request_number(self, event=None):
        selected = self.tree.selection()
        if not selected:
            return
        request_numbers = []
        for item_id in selected:
            vals = self.tree.item(item_id, "values")
            req_number = vals[2] if len(vals) > 2 else ""
            if req_number:
                request_numbers.append(str(req_number))
        if not request_numbers:
            self._log("(la fila seleccionada no tiene un Request # que copiar)")
            return
        text = "\n".join(request_numbers)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._log(f"Copiado al portapapeles: {', '.join(request_numbers)}")

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _maximize_window(self):
        try:
            self.state("zoomed")
        except tk.TclError:
            try:
                self.attributes("-zoomed", True)
            except tk.TclError:
                self.geometry(f"{self.winfo_screenwidth()}x{self.winfo_screenheight()}+0+0")


def launch():
    app = ServiceNowTesterGUI()
    app.mainloop()


if __name__ == "__main__":
    launch()
