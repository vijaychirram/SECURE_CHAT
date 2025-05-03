import socket
import threading

def recvall(sock: socket.socket, n: int) -> bytes | None:
    """Read exactly n bytes or return None on EOF."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def send_bytes(sock: socket.socket, data: bytes) -> None:
    """
    Prefix data with its length (4 bytes, big‑endian) and send it.
    """
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length + data)

def receive_bytes(sock: socket.socket) -> bytes | None:
    """
    Read a 4‑byte length prefix, then that many bytes of payload.
    """
    raw_len = recvall(sock, 4)
    if not raw_len:
        return None
    msg_len = int.from_bytes(raw_len, 'big')
    return recvall(sock, msg_len)

def start_server(port: int, on_message_callback):
    """
    Start a background TCP server on 0.0.0.0:port.
    For each client, spawn a thread that reads framed messages and calls:
        on_message_callback(conn, message_bytes)
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen()

    def handle_client(conn, addr):
        print(f"[Server] Connected by {addr}")
        while True:
            msg = receive_bytes(conn)
            if msg is None:
                break
            on_message_callback(conn, msg)
        print(f"[Server] Connection closed {addr}")
        conn.close()

    def accept_loop():
        print(f"[Server] Listening on port {port} …")
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return server

def connect_to_peer(host: str, port: int) -> socket.socket:
    """
    Connect to a TCP server (peer) and return the socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print(f"[Client] Connected to {host}:{port}")
    return sock

# ----------------
# Self‑test
# ----------------
if __name__ == "__main__":
    import time

    # 1) Start a tiny echo server on port 12345
    def echo_handler(conn, msg: bytes):
        print("[Server] Received:", msg)
        send_bytes(conn, b"ACK: " + msg)

    start_server(12345, echo_handler)
    time.sleep(1)   # give server a moment to bind

    # 2) Connect as a client, send a message, read response
    client = connect_to_peer('127.0.0.1', 12345)
    send_bytes(client, b'hello server')
    resp = receive_bytes(client)
    print("[Client] Got   :", resp)
    client.close()

    # Keep server alive a few seconds so you see logs:
    time.sleep(3)
