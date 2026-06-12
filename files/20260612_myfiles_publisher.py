#!/usr/bin/env python3
"""
myfiles_publisher.py
Desktop uploader/manager for sergiolunamedel-arch/MyFiles on GitHub Pages.

Features:
  - Drag & drop OR browse to upload any file type
  - Live file list with download links
  - Delete files with one click
  - Token stored in config (same pattern as BookForge)
  - Also publishes the index.html to GitHub on first run

Requirements: pip install tkinterdnd2   (optional, enables native drag-and-drop)
              Standard library only otherwise.
"""

import json
import os
import sys
import base64
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime
import urllib.request
import urllib.error
import webbrowser

# ── Optional native drag-and-drop ────────────────────────────────────────────
try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    HAS_DND = True
except ImportError:
    HAS_DND = False

# ── Config ────────────────────────────────────────────────────────────────────
REPO       = "sergiolunamedel-arch/MyFiles"
API_BASE   = f"https://api.github.com/repos/{REPO}"
PAGES_URL  = f"https://sergiolunamedel-arch.github.io/MyFiles/"
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "myfiles_config.json")

# ── Color palette (matches the dark web theme) ────────────────────────────────
T = {
    "bg":      "#0f0f1a",
    "card":    "#161627",
    "border":  "#252540",
    "text":    "#c8c6d0",
    "accent":  "#e2b714",
    "muted":   "#8886a0",
    "error":   "#e05555",
    "success": "#4ade80",
}

# ── GitHub API client ─────────────────────────────────────────────────────────
class GHClient:
    def __init__(self, token: str):
        self.token  = token
        self.branch = "main"
        self.headers = {
            "Content-Type":  "application/json",
            "Accept":        "application/vnd.github.v3+json",
            "User-Agent":    "MyFilesPublisher/1.0",
            "Authorization": f"token {token}",
        }

    def get_branch(self):
        try:
            req = urllib.request.Request(API_BASE, headers=self.headers)
            with urllib.request.urlopen(req, timeout=10) as r:
                self.branch = json.loads(r.read()).get("default_branch", "main")
        except Exception:
            pass

    def get_sha(self, path: str):
        try:
            url = f"{API_BASE}/contents/{path}?ref={self.branch}"
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read()).get("sha")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise

    def push_file(self, repo_path: str, data: bytes, message: str, sha=None, text=True):
        encoded = base64.b64encode(data).decode("ascii")
        payload = {"message": message, "content": encoded, "branch": self.branch}
        if sha:
            payload["sha"] = sha
        req = urllib.request.Request(
            f"{API_BASE}/contents/{repo_path}",
            data=json.dumps(payload).encode(),
            headers=self.headers,
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())

    def delete_file(self, repo_path: str, sha: str, message: str):
        payload = {"message": message, "sha": sha, "branch": self.branch}
        req = urllib.request.Request(
            f"{API_BASE}/contents/{repo_path}",
            data=json.dumps(payload).encode(),
            headers=self.headers,
            method="DELETE",
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    def list_files(self, folder: str = "files"):
        try:
            url = f"{API_BASE}/contents/{folder}?ref={self.branch}"
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return []
            raise

    def validate_token(self):
        """Quick check: try to read repo info."""
        req = urllib.request.Request(API_BASE, headers=self.headers)
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 200


# ── Main app ──────────────────────────────────────────────────────────────────
class MyFilesApp:

    def __init__(self, root):
        self.root   = root
        self.root.title("MyFiles Publisher")
        self.root.geometry("720x580")
        self.root.configure(bg=T["bg"])
        self.root.resizable(True, True)

        self.config  = self._load_config()
        self.client  = None
        self.gh_files = []   # list of dicts from GitHub API

        self._build_ui()
        self._init_client_async()

    # ── Config ────────────────────────────────────────────────────────────────
    def _load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r") as f:
                    return json.load(f)
        except Exception:
            pass
        return {"github_token": ""}

    def _save_config(self):
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(self.config, f, indent=2)
        except Exception:
            pass

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Header bar ──────────────────────────────────────────────────────
        hdr = tk.Frame(self.root, bg=T["card"], pady=10)
        hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg=T["accent"], height=3).pack(fill=tk.X, side=tk.TOP)
        inner = tk.Frame(hdr, bg=T["card"])
        inner.pack(fill=tk.X, padx=20, pady=(8, 0))
        tk.Label(inner, text="🗂  MyFiles Publisher", font=("Segoe UI", 14, "bold"),
                 bg=T["card"], fg=T["accent"]).pack(side=tk.LEFT)
        tk.Button(inner, text="⚙ Token", command=self._ask_token,
                  bg=T["card"], fg=T["muted"], font=("Segoe UI", 9),
                  relief=tk.FLAT, padx=10, cursor="hand2",
                  activebackground=T["border"]).pack(side=tk.RIGHT)
        tk.Button(inner, text="🌐 Abrir web", command=lambda: webbrowser.open(PAGES_URL),
                  bg=T["card"], fg=T["muted"], font=("Segoe UI", 9),
                  relief=tk.FLAT, padx=10, cursor="hand2",
                  activebackground=T["border"]).pack(side=tk.RIGHT)

        # ── Drop zone ────────────────────────────────────────────────────────
        drop_frame = tk.Frame(self.root, bg=T["bg"], padx=16, pady=12)
        drop_frame.pack(fill=tk.X)

        self.drop_zone = tk.Frame(
            drop_frame, bg=T["card"],
            highlightbackground=T["border"], highlightthickness=2,
            cursor="hand2",
        )
        self.drop_zone.pack(fill=tk.X, ipady=18)

        self.drop_lbl = tk.Label(
            self.drop_zone,
            text="📂  Arrastra archivos aquí  —  o haz clic para seleccionar",
            font=("Segoe UI", 11), bg=T["card"], fg=T["muted"],
        )
        self.drop_lbl.pack(expand=True)

        # Bind click on the whole zone to file picker
        for w in (self.drop_zone, self.drop_lbl):
            w.bind("<Button-1>", lambda e: self._browse_files())
            w.bind("<Enter>",    lambda e: self.drop_zone.config(highlightbackground=T["accent"]))
            w.bind("<Leave>",    lambda e: self.drop_zone.config(highlightbackground=T["border"]))

        # Native drag-and-drop if available
        if HAS_DND:
            self.drop_zone.drop_target_register(DND_FILES)
            self.drop_zone.dnd_bind("<<Drop>>", self._on_dnd_drop)

        # ── Upload progress ──────────────────────────────────────────────────
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            drop_frame, variable=self.progress_var, maximum=100,
            mode="determinate", length=200
        )
        # will be packed/unpacked dynamically

        # ── File list ────────────────────────────────────────────────────────
        list_outer = tk.Frame(self.root, bg=T["bg"], padx=16)
        list_outer.pack(fill=tk.BOTH, expand=True)

        # Header row
        list_hdr = tk.Frame(list_outer, bg=T["bg"])
        list_hdr.pack(fill=tk.X, pady=(4, 6))
        tk.Label(list_hdr, text="Archivos en el repositorio",
                 font=("Segoe UI", 10, "bold"), bg=T["bg"], fg=T["muted"]).pack(side=tk.LEFT)
        tk.Button(list_hdr, text="↻ Actualizar", command=self._refresh_list,
                  bg=T["bg"], fg=T["accent"], font=("Segoe UI", 9),
                  relief=tk.FLAT, cursor="hand2", padx=6,
                  activebackground=T["border"]).pack(side=tk.RIGHT)

        # Scrollable list
        canvas_frame = tk.Frame(list_outer, bg=T["border"], highlightthickness=0)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(canvas_frame)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas = tk.Canvas(canvas_frame, bg=T["bg"],
                                highlightthickness=0, yscrollcommand=sb.set)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.config(command=self.canvas.yview)
        self.list_inner = tk.Frame(self.canvas, bg=T["bg"])
        self._list_wid  = self.canvas.create_window((0, 0), window=self.list_inner, anchor="nw")
        self.list_inner.bind("<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>",
            lambda e: self.canvas.itemconfig(self._list_wid, width=e.width))
        self.canvas.bind("<MouseWheel>",
            lambda e: self.canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        # ── Status bar ───────────────────────────────────────────────────────
        self.status_var = tk.StringVar(value="Iniciando…")
        status_bar = tk.Frame(self.root, bg=T["card"], pady=6)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_lbl = tk.Label(status_bar, textvariable=self.status_var,
                                   font=("Segoe UI", 9), bg=T["card"], fg=T["accent"])
        self.status_lbl.pack(padx=14)

    # ── Status helper ────────────────────────────────────────────────────────
    def _status(self, msg, color=None):
        self.status_var.set(msg)
        self.status_lbl.config(fg=color or T["accent"])

    # ── Init client ─────────────────────────────────────────────────────────
    def _init_client_async(self):
        token = self.config.get("github_token", "").strip()
        if not token:
            self.root.after(200, self._ask_token)
            return
        self.client = GHClient(token)
        threading.Thread(target=self._validate_and_load, daemon=True).start()

    def _validate_and_load(self):
        try:
            self.client.get_branch()
            self.client.validate_token()
            self.root.after(0, lambda: self._status("✓ Conectado a GitHub", T["success"]))
            self.root.after(0, self._refresh_list)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                self.root.after(0, lambda: self._status("✗ Token inválido — configura uno nuevo", T["error"]))
                self.root.after(500, self._ask_token)
            else:
                self.root.after(0, lambda: self._status(f"✗ Error GitHub {e.code}", T["error"]))
        except Exception as ex:
            self.root.after(0, lambda: self._status(f"✗ Sin conexión: {ex}", T["error"]))

    # ── Token dialog ─────────────────────────────────────────────────────────
    def _ask_token(self):
        win = tk.Toplevel(self.root)
        win.title("GitHub Token")
        win.configure(bg=T["bg"])
        win.geometry("500x300")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text="🔑  GitHub Personal Access Token",
                 font=("Segoe UI", 13, "bold"), bg=T["bg"], fg=T["accent"]).pack(pady=(20, 4))
        tk.Label(win,
                 text=(
                     "Necesitas un token con acceso de escritura al repositorio.\n\n"
                     "Token clásico: Settings → Developer settings →\n"
                     "  Personal access tokens → scope 'repo'\n\n"
                     "Fine-grained: selecciona el repo y habilita\n"
                     "  Repository permissions → Contents → Read and write"
                 ),
                 font=("Segoe UI", 9), bg=T["bg"], fg=T["muted"],
                 justify=tk.LEFT).pack(padx=30)

        var = tk.StringVar(value=self.config.get("github_token", ""))
        entry = tk.Entry(win, textvariable=var, show="*", font=("Segoe UI", 11),
                         bg=T["card"], fg=T["text"], insertbackground=T["accent"],
                         relief=tk.FLAT, width=44,
                         highlightthickness=1, highlightbackground=T["border"])
        entry.pack(pady=(12, 4), padx=30, ipady=6, fill=tk.X)
        entry.focus_set()

        def confirm():
            tok = var.get().strip()
            if not tok:
                messagebox.showwarning("Token requerido", "Ingresa tu token.", parent=win)
                return
            self.config["github_token"] = tok
            self._save_config()
            self.client = GHClient(tok)
            win.destroy()
            threading.Thread(target=self._validate_and_load, daemon=True).start()

        btn_row = tk.Frame(win, bg=T["bg"])
        btn_row.pack(pady=12)
        tk.Button(btn_row, text="Cancelar", command=win.destroy,
                  bg=T["card"], fg=T["muted"], relief=tk.FLAT, padx=14, pady=6).pack(side=tk.LEFT, padx=6)
        tk.Button(btn_row, text="✓ Guardar y conectar", command=confirm,
                  bg=T["accent"], fg="#000", font=("Segoe UI", 10, "bold"),
                  relief=tk.FLAT, padx=14, pady=6, cursor="hand2").pack(side=tk.LEFT, padx=6)
        entry.bind("<Return>", lambda e: confirm())

    # ── Browse & Upload ──────────────────────────────────────────────────────
    def _browse_files(self):
        paths = filedialog.askopenfilenames(title="Seleccionar archivos para subir")
        if paths:
            self._upload_files(list(paths))

    def _on_dnd_drop(self, event):
        # tkinterdnd2 returns paths as a space-separated string,
        # with paths that contain spaces wrapped in {}
        raw   = event.data.strip()
        paths = []
        i = 0
        while i < len(raw):
            if raw[i] == '{':
                end = raw.index('}', i)
                paths.append(raw[i+1:end])
                i = end + 2
            else:
                j = raw.find(' ', i)
                if j == -1:
                    paths.append(raw[i:])
                    break
                paths.append(raw[i:j])
                i = j + 1
        if paths:
            self._upload_files(paths)

    def _upload_files(self, paths):
        if not self.client:
            messagebox.showwarning("Sin token", "Configura tu GitHub token primero.")
            return
        threading.Thread(target=self._do_upload, args=(paths,), daemon=True).start()

    def _do_upload(self, paths):
        total = len(paths)
        self.root.after(0, lambda: self.progress_bar.pack(fill=tk.X, pady=4))

        for i, local_path in enumerate(paths):
            fname = os.path.basename(local_path)
            # Prefix with date so sorting works on the web
            datepfx = datetime.now().strftime("%Y%m%d") + "_"
            if not fname[:8].isdigit():
                repo_name = datepfx + fname
            else:
                repo_name = fname

            repo_path = f"files/{repo_name}"
            self.root.after(0, lambda n=fname: self._status(f"⏳ Subiendo {n}…"))

            try:
                with open(local_path, "rb") as f:
                    data = f.read()
                sha = self.client.get_sha(repo_path)
                self.client.push_file(
                    repo_path, data,
                    f"📎 Upload {repo_name} via MyFilesPublisher",
                    sha=sha, text=False,
                )
                pct = (i + 1) / total * 100
                self.root.after(0, lambda p=pct: self.progress_var.set(p))
                self.root.after(0, lambda n=fname: self._status(f"✓ {n} subido", T["success"]))
            except Exception as ex:
                self.root.after(0, lambda e=str(ex), n=fname:
                    self._status(f"✗ Error subiendo {n}: {e}", T["error"]))

        self.root.after(0, lambda: self.progress_bar.pack_forget())
        self.root.after(0, lambda: self.progress_var.set(0))
        self.root.after(500, self._refresh_list)

    # ── File list ────────────────────────────────────────────────────────────
    def _refresh_list(self):
        if not self.client:
            self._status("Configura tu token primero.", T["muted"])
            return
        self._status("Cargando lista…")
        threading.Thread(target=self._do_refresh, daemon=True).start()

    def _do_refresh(self):
        try:
            files = self.client.list_files("files")
            self.gh_files = files if isinstance(files, list) else []
            self.root.after(0, self._render_list)
        except Exception as ex:
            self.root.after(0, lambda e=str(ex):
                self._status(f"✗ Error al cargar lista: {e}", T["error"]))

    def _render_list(self):
        for w in self.list_inner.winfo_children():
            w.destroy()

        if not self.gh_files:
            tk.Label(self.list_inner,
                     text="📭  No hay archivos todavía.\nSube el primero usando el área de arriba.",
                     font=("Segoe UI", 10), bg=T["bg"], fg=T["muted"],
                     justify=tk.CENTER).pack(pady=32)
            self._status(f"0 archivos en el repositorio")
            return

        total_size = sum(f.get("size", 0) for f in self.gh_files)

        for f in sorted(self.gh_files, key=lambda x: x.get("name", "").lower()):
            fname    = f.get("name", "")
            sha      = f.get("sha", "")
            size     = f.get("size", 0)
            dl_url   = f.get("download_url", "")
            display  = fname.replace(datetime.now().strftime("%Y%m%d") + "_", "", 1)
            # strip any date prefix for display
            import re
            display = re.sub(r"^\d{8}_", "", display)

            row = tk.Frame(self.list_inner, bg=T["card"],
                           highlightbackground=T["border"], highlightthickness=1)
            row.pack(fill=tk.X, pady=2, padx=0)

            info = tk.Frame(row, bg=T["card"])
            info.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=12, pady=8)
            tk.Label(info, text=display, font=("Segoe UI", 10, "bold"),
                     bg=T["card"], fg=T["text"], anchor="w").pack(anchor="w")
            tk.Label(info, text=self._fmt_size(size),
                     font=("Segoe UI", 8), bg=T["card"], fg=T["muted"],
                     anchor="w").pack(anchor="w")

            btns = tk.Frame(row, bg=T["card"])
            btns.pack(side=tk.RIGHT, padx=8, pady=6)

            if dl_url:
                tk.Button(btns, text="⬇", font=("Segoe UI", 10),
                          command=lambda u=dl_url: webbrowser.open(u),
                          bg=T["card"], fg=T["muted"], relief=tk.FLAT,
                          width=3, cursor="hand2",
                          activebackground=T["border"]).pack(side=tk.LEFT, padx=2)

            tk.Button(btns, text="🗑", font=("Segoe UI", 10),
                      command=lambda n=fname, s=sha: self._confirm_delete(n, s),
                      bg=T["card"], fg=T["error"], relief=tk.FLAT,
                      width=3, cursor="hand2",
                      activebackground=T["border"]).pack(side=tk.LEFT, padx=2)

        self._status(f"✓ {len(self.gh_files)} archivos  ·  {self._fmt_size(total_size)} total")

    @staticmethod
    def _fmt_size(b):
        if b < 1024:    return f"{b} B"
        if b < 1048576: return f"{b/1024:.1f} KB"
        return f"{b/1048576:.1f} MB"

    # ── Delete ────────────────────────────────────────────────────────────────
    def _confirm_delete(self, fname, sha):
        display = __import__("re").sub(r"^\d{8}_", "", fname)
        if messagebox.askyesno(
            "Eliminar archivo",
            f"¿Eliminar «{display}» del repositorio?\n\nEsta acción no se puede deshacer.",
            icon="warning"
        ):
            threading.Thread(target=self._do_delete, args=(fname, sha), daemon=True).start()

    def _do_delete(self, fname, sha):
        self.root.after(0, lambda: self._status(f"⏳ Eliminando {fname}…"))
        try:
            self.client.delete_file(
                f"files/{fname}", sha,
                f"🗑 Delete {fname} via MyFilesPublisher"
            )
            self.root.after(0, lambda: self._status(f"✓ {fname} eliminado", T["success"]))
            self.root.after(500, self._refresh_list)
        except Exception as ex:
            self.root.after(0, lambda e=str(ex):
                self._status(f"✗ Error: {e}", T["error"]))


# ── Entry point ────────────────────────────────────────────────────────────────
def main():
    if HAS_DND:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()

    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure("TScrollbar",
                    background=T["border"], troughcolor=T["bg"],
                    bordercolor=T["bg"], arrowcolor=T["text"],
                    lightcolor=T["card"], darkcolor=T["card"])
    style.configure("Horizontal.TProgressbar",
                    troughcolor=T["border"], background=T["accent"])

    app = MyFilesApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
