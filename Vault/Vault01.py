#!/usr/bin/env python3
"""
Password-protected Virtual Folder (Single-file Encrypted Vault)

- Stores everything INSIDE a single .vault file (SQLite DB with encrypted blobs)
- AES-GCM encryption (via cryptography)
- Key derived from password via PBKDF2-HMAC-SHA256 (random salt per vault)
- Filenames & metadata are encrypted too
- Optional drag-and-drop support via tkinterdnd2
- Cross-platform Tkinter GUI

Usage:
    python vault.py

Dependencies:
    pip install cryptography
    # optional for drag & drop:
    pip install tkinterdnd2
"""

import os
import sqlite3
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# --- Crypto primitives (cryptography) ---
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import secrets
import base64

# typing
from typing import List, Optional

# --- Optional drag-and-drop ---
HAS_DND = False
try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    HAS_DND = True
except Exception:
    pass

VAULT_SCHEMA_VERSION = 1
PBKDF_ITERATIONS = 200_000
SALT_BYTES = 16
NONCE_BYTES = 12


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def enc_json(obj: dict, key: bytes) -> bytes:
    aes = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_BYTES)
    plaintext = json.dumps(obj).encode("utf-8")
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce + ct


def dec_json(blob: bytes, key: bytes) -> dict:
    aes = AESGCM(key)
    nonce, ct = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    pt = aes.decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))


def enc_bytes(data: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_BYTES)
    ct = aes.encrypt(nonce, data, None)
    return nonce + ct


def dec_bytes(blob: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    nonce, ct = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    return aes.decrypt(nonce, ct, None)


# --- Vault (SQLite + encrypted blobs) ---
class Vault:
    def __init__(self, path: str):
        self.path = path
        self.conn: Optional[sqlite3.Connection] = None
        self.key: Optional[bytes] = None

    def connect(self, create_if_missing=False):
        new = not os.path.exists(self.path)
        if new and not create_if_missing:
            raise FileNotFoundError(self.path)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        if new:
            self._init_db()
        return new

    def _init_db(self):
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE meta(
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE entries(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                enc_meta BLOB NOT NULL,
                enc_data BLOB NOT NULL
            );
            """
        )
        salt = secrets.token_bytes(SALT_BYTES)
        cur.execute(
            "INSERT INTO meta(k,v) VALUES (?,?)",
            ("schema_version", str(VAULT_SCHEMA_VERSION)),
        )
        cur.execute("INSERT INTO meta(k,v) VALUES (?,?)", ("salt_b64", b64e(salt)))
        cur.execute("INSERT INTO meta(k,v) VALUES (?,?)", ("verifier_b64", ""))
        self.conn.commit()

    def _get_salt(self) -> bytes:
        cur = self.conn.execute("SELECT v FROM meta WHERE k='salt_b64'")
        row = cur.fetchone()
        if not row:
            raise RuntimeError("Vault missing salt.")
        return b64d(row[0])

    def _get_verifier(self) -> Optional[bytes]:
        cur = self.conn.execute("SELECT v FROM meta WHERE k='verifier_b64'")
        row = cur.fetchone()
        if not row or not row[0]:
            return None
        return b64d(row[0])

    def _set_verifier(self, verifier: bytes):
        self.conn.execute(
            "UPDATE meta SET v=? WHERE k='verifier_b64'", (b64e(verifier),)
        )
        self.conn.commit()

    def unlock(self, password: str):
        salt = self._get_salt()
        key = derive_key(password, salt)
        verifier = self._get_verifier()
        if verifier is None or len(verifier) == 0:
            blob = enc_bytes(b"VAULT-VERIFIER", key)
            self._set_verifier(blob)
            self.key = key
            return True
        try:
            pt = dec_bytes(verifier, key)
            if pt != b"VAULT-VERIFIER":
                raise InvalidTag("Bad verifier content.")
            self.key = key
            return True
        except Exception:
            return False

    def list(self) -> List[dict]:
        if self.key is None or self.conn is None:
            raise RuntimeError("Vault is locked.")
        items: List[dict] = []
        for row in self.conn.execute("SELECT id, enc_meta FROM entries ORDER BY id ASC"):
            _id, enc_meta = row
            try:
                meta = dec_json(enc_meta, self.key)
            except Exception:
                meta = {"name": "<unreadable>", "size": -1, "mtime": 0}
            meta["id"] = _id
            items.append(meta)
        return items

    def add_file(self, src_path: str):
        if self.key is None or self.conn is None:
            raise RuntimeError("Vault is locked.")
        name = os.path.basename(src_path)
        try:
            stat = os.stat(src_path)
            size = stat.st_size
            mtime = stat.st_mtime
            with open(src_path, "rb") as f:
                data = f.read()
        except Exception as e:
            raise RuntimeError(f"Failed to read {src_path}: {e}") from e

        meta = {"name": name, "size": size, "mtime": mtime}
        enc_meta = enc_json(meta, self.key)
        enc_data = enc_bytes(data, self.key)
        self.conn.execute("INSERT INTO entries(enc_meta, enc_data) VALUES (?,?)", (enc_meta, enc_data))
        self.conn.commit()

    def delete_items(self, ids: List[int]):
        if not ids or self.conn is None:
            return
        qmarks = ",".join("?" for _ in ids)
        self.conn.execute(f"DELETE FROM entries WHERE id IN ({qmarks})", ids)
        self.conn.commit()

    def extract_item(self, item_id: int, dest_dir: str):
        if self.key is None or self.conn is None:
            raise RuntimeError("Vault is locked.")
        cur = self.conn.execute("SELECT enc_meta, enc_data FROM entries WHERE id=?", (item_id,))
        row = cur.fetchone()
        if not row:
            raise FileNotFoundError(f"Item id {item_id} not found.")
        enc_meta, enc_data = row
        meta = dec_json(enc_meta, self.key)
        data = dec_bytes(enc_data, self.key)
        out_path = os.path.join(dest_dir, meta["name"])
        base, ext = os.path.splitext(out_path)
        i = 1
        final_path = out_path
        while os.path.exists(final_path):
            final_path = f"{base} ({i}){ext}"
            i += 1
        with open(final_path, "wb") as f:
            f.write(data)
        return final_path


# --- Tkinter GUI ---
class VaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Virtual Folder (Vault)")
        self.vault: Optional[Vault] = None
        self._build_ui()

    def _build_ui(self):
        self.root.geometry("820x520")
        self.root.minsize(700, 420)

        topbar = ttk.Frame(self.root, padding=8)
        topbar.pack(side=tk.TOP, fill=tk.X)

        self.vault_path_var = tk.StringVar(value="No vault open")
        self.status_var = tk.StringVar(value="Locked")

        # Separate buttons
        ttk.Button(topbar, text="Create Vault…", command=self.create_vault).pack(side=tk.LEFT)
        ttk.Button(topbar, text="Open Vault…", command=self.open_vault).pack(side=tk.LEFT, padx=(8,0))
        ttk.Button(topbar, text="Lock/Close", command=self.lock_close).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Separator(topbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)

        ttk.Button(topbar, text="Add Files…", command=self.add_files_dialog).pack(side=tk.LEFT)
        self.add_hint = ttk.Label(topbar, text="(or drag files here)" if HAS_DND else "(drag & drop requires tkinterdnd2)")
        self.add_hint.pack(side=tk.LEFT, padx=(6,0))

        ttk.Button(topbar, text="Extract Selected…", command=self.extract_selected).pack(side=tk.RIGHT)
        ttk.Button(topbar, text="Delete Selected", command=self.delete_selected).pack(side=tk.RIGHT, padx=(8,0))

        info = ttk.Frame(self.root, padding=(8, 0))
        info.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(info, textvariable=self.vault_path_var).pack(side=tk.LEFT)
        ttk.Label(info, textvariable=self.status_var, foreground="gray").pack(side=tk.RIGHT)

        # Treeview list
        list_frame = ttk.Frame(self.root, padding=8)
        list_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        cols = ("name", "size", "mtime", "id")
        self.tree = ttk.Treeview(list_frame, columns=cols, show="headings", selectmode="extended")
        for c, w, a in [("name", 360, tk.W), ("size", 110, tk.E), ("mtime", 150, tk.E), ("id", 60, tk.E)]:
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor=a)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Drag-and-drop
        if HAS_DND and isinstance(self.root, TkinterDnD.Tk):
            self.tree.drop_target_register(DND_FILES)
            self.tree.dnd_bind("<<Drop>>", self._on_drop)

        # Shortcuts
        self.root.bind("<Delete>", lambda e: self.delete_selected())
        self.root.bind("<Control-e>", lambda e: self.extract_selected())
        self.root.bind("<Control-o>", lambda e: self.open_vault())
        self.root.bind("<Control-a>", lambda e: self.add_files_dialog())

    # --- Separate vault operations ---
    def create_vault(self):
        path = filedialog.asksaveasfilename(title="Create Vault", defaultextension=".vault", filetypes=[("Vault files", "*.vault"), ("All files", "*.*")])
        if not path:
            return
        v = Vault(path)
        try:
            v.connect(create_if_missing=True)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create vault:\n{e}")
            return
        pw = self._prompt_password(confirm=True, title="Create vault password")
        if pw is None:
            v.conn.close()
            return
        if not v.unlock(pw):
            messagebox.showerror("Error", "Failed to set vault password.")
            v.conn.close()
            return
        self.vault = v
        self.vault_path_var.set(f"Vault: {os.path.abspath(path)}")
        self.status_var.set("Unlocked")
        self.refresh_list()

    def open_vault(self):
        path = filedialog.askopenfilename(title="Open Vault", filetypes=[("Vault files", "*.vault"), ("All files", "*.*")])
        if not path:
            return
        v = Vault(path)
        try:
            v.connect(create_if_missing=False)
        except FileNotFoundError:
            messagebox.showerror("Error", f"Vault file not found:\n{path}")
            return
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open vault:\n{e}")
            return
        pw = self._prompt_password(confirm=False, title="Enter vault password")
        if pw is None:
            v.conn.close()
            return
        if not v.unlock(pw):
            messagebox.showerror("Error", "Wrong password.")
            v.conn.close()
            return
        self.vault = v
        self.vault_path_var.set(f"Vault: {os.path.abspath(path)}")
        self.status_var.set("Unlocked")
        self.refresh_list()

    # --- Password prompt ---
    def _prompt_password(self, confirm=False, title="Password"):
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        ttk.Label(dlg, text="Password:").pack(padx=12, pady=(12, 4))
        pw1 = ttk.Entry(dlg, show="*")
        pw1.pack(padx=12, pady=(0, 8), fill=tk.X)
        pw2 = None
        if confirm:
            ttk.Label(dlg, text="Confirm password:").pack(padx=12, pady=(4, 4))
            pw2 = ttk.Entry(dlg, show="*")
            pw2.pack(padx=12, pady=(0, 12), fill=tk.X)
        out = {"pw": None}

        def on_ok():
            p1 = pw1.get()
            if not p1:
                messagebox.showerror("Error", "Password cannot be empty.")
                return
            if confirm and pw2 and p1 != pw2.get():
                messagebox.showerror("Error", "Passwords do not match.")
                return
            out["pw"] = p1
            dlg.destroy()

        def on_cancel():
            dlg.destroy()

        btns = ttk.Frame(dlg)
        btns.pack(padx=12, pady=12)
        ttk.Button(btns, text="OK", command=on_ok).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=6)
        dlg.wait_window()
        return out["pw"]

    # --- Other vault GUI methods (unchanged) ---
    def lock_close(self):
        if self.vault and self.vault.conn:
            try:
                self.vault.conn.close()
            except Exception:
                pass
        self.vault = None
        self.vault_path_var.set("No vault open")
        self.status_var.set("Locked")
        for i in self.tree.get_children():
            self.tree.delete(i)

    def refresh_list(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        if not self.vault:
            return
        try:
            items = self.vault.list()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return
        for m in items:
            self.tree.insert("", tk.END, values=(m.get("name",""), m.get("size",-1), int(m.get("mtime",0)), m.get("id",-1)))

    def add_files_dialog(self):
        if not self.vault:
            messagebox.showinfo("No Vault", "Open or create a vault first.")
            return
        paths = filedialog.askopenfilenames(title="Add files to vault")
        if not paths:
            return
        self._add_files(paths)

    def _on_drop(self, event):
        if not self.vault:
            return
        raw = event.data
        paths: List[str] = []
        token = ""
        in_brace = False
        for ch in raw:
            if ch == "{":
                in_brace = True
                token = ""
            elif ch == "}":
                in_brace = False
                paths.append(token)
                token = ""
            elif ch in ("\n", " "):
                if in_brace:
                    token += ch
                else:
                    if token:
                        paths.append(token)
                        token = ""
            else:
                token += ch
        if token:
            paths.append(token)
        clean = [p for p in paths if os.path.isfile(p)]
        if clean:
            self._add_files(clean)

    def _add_files(self, paths: List[str]):
        if not self.vault:
            return
        added = 0
        errors: List[str] = []
        self.status_var.set("Encrypting…")
        self.root.update_idletasks()
        for p in paths:
            try:
                self.vault.add_file(p)
                added += 1
            except Exception as e:
                errors.append(f"{os.path.basename(p)}: {e}")
        self.refresh_list()
        self.status_var.set(f"Added {added} file(s)")
        if errors:
            messagebox.showwarning("Some files failed", "\n".join(errors[:10]) + ("\n…" if len(errors)>10 else ""))

    def _selected_ids(self) -> List[int]:
        ids: List[int] = []
        for item in self.tree.selection():
            vals = self.tree.item(item, "values")
            if not vals:
                continue
            try:
                ids.append(int(vals[3]))
            except Exception:
                pass
        return ids

    def delete_selected(self):
        if not self.vault:
            return
        ids = self._selected_ids()
        if not ids:
            return
        if messagebox.askyesno("Delete", f"Delete {len(ids)} selected items?"):
            self.vault.delete_items(ids)
            self.refresh_list()

    def extract_selected(self):
        if not self.vault:
            return
        ids = self._selected_ids()
        if not ids:
            return
        dest = filedialog.askdirectory(title="Select destination folder")
        if not dest:
            return
        for i in ids:
            try:
                out = self.vault.extract_item(i, dest)
                print(f"Extracted: {out}")
            except Exception as e:
                messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    if HAS_DND:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    app = VaultApp(root)
    root.mainloop()
