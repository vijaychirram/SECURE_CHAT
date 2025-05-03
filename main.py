import argparse
import threading
import time

from crypto_utils import derive_key, encrypt_message, decrypt_message
from network      import start_server, connect_to_peer, send_bytes, receive_bytes

def run_server(port: int, key: bytes):
    """
    Start a server that decrypts each incoming message, prints it,
    then replies with an encrypted ACK.
    """
    def handler(conn, enc_msg: bytes):
        # 1) Decrypt incoming
        try:
            plaintext = decrypt_message(key, enc_msg)
        except Exception as e:
            print("[Server] Decryption failed:", e)
            return

        print(f"[Server] Received (decrypted): {plaintext!r}")

        # 2) Send back an ACK under the same key
        reply = f"ACK: {plaintext}"
        enc_reply = encrypt_message(key, reply)
        send_bytes(conn, enc_reply)

    start_server(port, handler)
    print(f"[Server] Running on port {port}. Ctrl‑C to quit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Server] Shutting down.")

def run_client(host: str, port: int, key: bytes):
    """
    Connect to server, then loop:
      * read user line
      * encrypt & send
      * receive & decrypt reply
    """
    sock = connect_to_peer(host, port)
    print("[Client] Type messages and press Enter. Ctrl‑C to quit.")
    try:
        while True:
            line = input("You: ")
            if not line:
                continue

            enc = encrypt_message(key, line)
            send_bytes(sock, enc)

            enc_resp = receive_bytes(sock)
            if enc_resp is None:
                print("[Client] Server closed connection.")
                break

            resp = decrypt_message(key, enc_resp)
            print(f"[Client] Server replied (decrypted): {resp!r}")

    except KeyboardInterrupt:
        print("\n[Client] Exiting.")
    finally:
        sock.close()

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Secure P2P CLI Demo")
    p.add_argument("--mode",   choices=["server","client"], required=True)
    p.add_argument("--host",   default="127.0.0.1", help="peer address (client mode)")
    p.add_argument("--port",   type=int, required=True)
    p.add_argument("--salt",   required=True,
                   help="hex-encoded salt (same on both sides)")
    args = p.parse_args()

    # 1) Hex‑decode the common salt
    salt_bytes = bytes.fromhex(args.salt)

    # 2) Prompt for passphrase & derive key
    pwd = input("Passphrase: ")
    key = derive_key(pwd, salt_bytes)

    # 3) Branch based on mode
    if args.mode == "server":
        run_server(args.port, key)
    else:
        run_client(args.host, args.port, key)
