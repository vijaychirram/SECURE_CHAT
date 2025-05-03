import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import hashlib

from crypto_utils import derive_key, encrypt_message, decrypt_message
from network import start_server, connect_to_peer, send_bytes, receive_bytes

# Special plaintext marker for key rotation
REKEY_MARKER = "__REKEY__"

class ChatApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure P2P Chat")

        # Crypto and connection state
        self.passphrase = None
        self.salt = None
        self.key = None
        self.conn = None

        # Build UI frames
        self._build_setup_frame()
        self._build_chat_frame()

        # Show setup first
        self.setup_frame.pack(fill=tk.BOTH, expand=True)
        self.chat_frame.pack_forget()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _build_setup_frame(self):
        f = tk.Frame(self.root, padx=10, pady=10)
        self.setup_frame = f

        tk.Label(f, text="Mode:").grid(row=0, column=0, sticky=tk.W)
        self.mode_var = tk.StringVar(value="server")
        tk.Radiobutton(f, text="Server", variable=self.mode_var, value="server").grid(row=0, column=1)
        tk.Radiobutton(f, text="Client", variable=self.mode_var, value="client").grid(row=0, column=2)

        tk.Label(f, text="Host:").grid(row=1, column=0, sticky=tk.W)
        self.host_entry = tk.Entry(f)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.grid(row=1, column=1, columnspan=2, sticky=tk.EW)

        tk.Label(f, text="Port:").grid(row=2, column=0, sticky=tk.W)
        self.port_entry = tk.Entry(f)
        self.port_entry.insert(0, "5000")
        self.port_entry.grid(row=2, column=1, columnspan=2, sticky=tk.EW)

        tk.Label(f, text="Passphrase:").grid(row=3, column=0, sticky=tk.W)
        self.pw_entry = tk.Entry(f, show="*")
        self.pw_entry.grid(row=3, column=1, columnspan=2, sticky=tk.EW)

        btn = tk.Button(f, text="Connect", command=self._on_connect)
        btn.grid(row=4, column=0, columnspan=3, pady=10)

        for i in range(3):
            f.grid_columnconfigure(i, weight=1)

    def _build_chat_frame(self):
        f = tk.Frame(self.root, padx=10, pady=10)
        self.chat_frame = f

        self.text_area = scrolledtext.ScrolledText(f, state=tk.DISABLED, wrap=tk.WORD, height=20)
        self.text_area.pack(fill=tk.BOTH, expand=True)

        bottom = tk.Frame(f)
        bottom.pack(fill=tk.X)

        self.msg_entry = tk.Entry(bottom)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.msg_entry.bind('<Return>', lambda e: self._send_message())

        tk.Button(bottom, text="Send", command=self._send_message).pack(side=tk.RIGHT)
        tk.Button(bottom, text="Re-Key", command=lambda: threading.Thread(target=self._trigger_rekey, daemon=True).start()).pack(side=tk.RIGHT, padx=5)

    def _on_connect(self):
        mode = self.mode_var.get()
        host = self.host_entry.get().strip()
        try:
            port = int(self.port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Port must be an integer")
            return

        pw = self.pw_entry.get()
        if not pw:
            messagebox.showerror("Error", "Passphrase cannot be empty")
            return

        # Initialize salt and key based on passphrase
        self.passphrase = pw
        self.salt = b"\x00" * 16
        self.key = derive_key(self.passphrase, self.salt)
        self._display("[Info] Key initialized")

        # Establish connection
        if mode == "server":
            def handler(conn, enc_msg):
                if self.conn is None:
                    self.conn = conn
                try:
                    pt = decrypt_message(self.key, enc_msg)
                except Exception:
                    return

                # check for rekey marker under old key
                if pt == REKEY_MARKER:
                    self._apply_rekey()
                else:
                    self._display(f"[C]{enc_msg.hex()}")
                    self._display(f"[P]{pt}")

            start_server(port, handler)
            self._display("[Info] Server listening...")

        else:
            try:
                sock = connect_to_peer(host, port)
                self.conn = sock
            except Exception as e:
                messagebox.showerror("Error", f"Connection failed: {e}")
                return

            def listen():
                while True:
                    enc = receive_bytes(self.conn)
                    if enc is None:
                        break
                    try:
                        pt = decrypt_message(self.key, enc)
                    except Exception:
                        continue
                    if pt == REKEY_MARKER:
                        self._apply_rekey()
                    else:
                        self._display(f"[C]{enc.hex()}")
                        self._display(f"[P]{pt}")

            threading.Thread(target=listen, daemon=True).start()
            self._display("[Info] Connected to server.")

        self.setup_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

    def _send_message(self):
        msg = self.msg_entry.get().strip()
        if not msg or not self.conn:
            return
        try:
            enc = encrypt_message(self.key, msg)
            send_bytes(self.conn, enc)
        except Exception as e:
            self._display(f"[Error] Send failed: {e}")
            return
        self._display(f"[C]{enc.hex()}")
        self._display(f"[P]You: {msg}")
        self.msg_entry.delete(0, tk.END)

    def _trigger_rekey(self):
        # 1) broadcast rekey marker under current key
        try:
            enc = encrypt_message(self.key, REKEY_MARKER)
            send_bytes(self.conn, enc)
        except Exception:
            return
        # 2) apply local key rotation
        self._apply_rekey()

    def _apply_rekey(self):
        # Deterministic salt rotation: hash previous salt
        self.salt = hashlib.sha256(self.salt).digest()[:16]
        self.key = derive_key(self.passphrase, self.salt)
        self._display("[Info] Key rotated")

    def _display(self, text: str):
        def append():
            self.text_area.config(state=tk.NORMAL)
            self.text_area.insert(tk.END, text + "\n")
            self.text_area.config(state=tk.DISABLED)
            self.text_area.yview(tk.END)
        self.text_area.after(0, append)

    def _on_close(self):
        try:
            if self.conn:
                self.conn.close()
        except:
            pass
        self.root.destroy()

if __name__ == "__main__":
    ChatApp()
