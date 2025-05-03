# Secure Instant P2P Chat

A Python/Tkinter prototype for end‑to‑end encrypted point‑to‑point messaging.

## Features

- AES‑256‑CBC encryption with per‑message IV
- PBKDF2‑HMAC‑SHA256 key derivation from a shared passphrase
- PKCS7 padding
- Frame‑based TCP transport (4‑byte length prefix)
- GUI (Tkinter) showing ciphertext (hex) and decrypted plaintext
- Manual, synchronized “Re‑Key” button to rotate the symmetric key

---

## 📋 Prerequisites

- Python 3.8 or newer
- Git (for cloning)
- Windows, macOS, or Linux

---

## 🔧 Installation & Setup

1. **Clone the repo**

   ```bash
   git clone https://github.com/Vijaychirram/SECURE_CHAT.git
   cd SECURE_CHAT
   ```

2. **Create & activate a virtual environment**

   ```bash
   # macOS/Linux
   python3 -m venv env
   source env/bin/activate

   # Windows (PowerShell)
   python -m venv env
   .\env\Scripts\Activate.ps1
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Running the GUI

Launch **two** instances: one in **Server** mode, one in **Client** mode.

### Server

```bash
python gui.py
```

- Mode: **Server**
- Host: (ignored)
- Port: e.g. `5000`
- Passphrase: shared secret (e.g. `secret123`)
- Click **Connect**

### Client

```bash
python gui.py
```

- Mode: **Client**
- Host: `127.0.0.1` (or Server’s IP)
- Port: same as Server (`5000`)
- Passphrase: **same** as Server
- Click **Connect**

---

## 💬 Using the Chat

- **Send a message**: Type into the bottom entry box, press **Enter** or click **Send**.

  ```
  [C]<ciphertext-hex>
  [P]You: <plaintext>
  ```

  The peer window shows the same ciphertext and the decrypted plaintext.

- **Rotate the key**: Click **Re‑Key** in **either** window.
  ```
  [Info] Key rotated
  ```
  Both peers will log the rotation and use the new key for subsequent messages.

---

## 🔄 Project Structure

```
secure_p2p_chat/
├── crypto_utils.py    # Key derivation, encrypt/decrypt routines
├── network.py         # TCP framing (send_bytes, receive_bytes)
├── gui.py             # Tkinter application (Server & Client modes)
├── main.py            # CLI demo (optional)
├── requirements.txt   # Python dependencies
└── README.md          # This file
```

---

## 🛠 Troubleshooting

- **Connection refused**: Ensure the Server GUI is running before the Client GUI connects.
- **Passphrase mismatch**: Both sides must use the same passphrase (case-sensitive).
- **Port in use**: Choose another unused TCP port (e.g. `6000`).

---

## 🔒 Security Notes

- Teaching prototype; not production-hardened.
- No message authentication (MAC) implemented; an active attacker could tamper.
- Key rotation is manual; consider automating after _N_ messages or _T_ seconds.

---
