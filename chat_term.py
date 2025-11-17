# python chat_term.py --mode server --port 5000
# python chat_term.py --mode client --host 127.0.0.1 --port 5000


import socket
import threading
import argparse
import sys
import getpass
import signal

ENC = "utf-8"
EXIT_CMD = "/exit"
PASSWORD = "lalith"

# Gracefully handle Ctrl+C
def sigint_handler(sig, frame):
    print("\n[!] Exiting chat.")
    sys.exit(0)

signal.signal(signal.SIGINT, sigint_handler)

# Receive messages
def recv_loop(conn, peer_name):
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                print(f"\n[*] {peer_name} disconnected.")
                break
            text = data.decode(ENC)
            print(f"\n{peer_name}: {text}\n> ", end="", flush=True)
            if text.strip() == EXIT_CMD:
                print(f"[*] {peer_name} exited.")
                break
    except (ConnectionResetError, ConnectionAbortedError):
        print(f"\n[*] Connection closed by {peer_name}.")
    finally:
        try:
            conn.shutdown(socket.SHUT_RD)
        except: pass

# Send messages
def send_loop(conn, peer_name):
    try:
        while True:
            msg = input("> ")
            conn.sendall(msg.encode(ENC))
            if msg.strip() == EXIT_CMD:
                print("[*] You exited.")
                break
    except (ConnectionResetError, ConnectionAbortedError):
        print(f"\n[*] Connection closed by {peer_name}.")
    finally:
        try:
            conn.shutdown(socket.SHUT_WR)
        except: pass

# Authenticate client
def authenticate(conn, mode):
    if mode == "server":
        # Server asks for password from client
        conn.sendall("PASSWORD:".encode(ENC))
        password = conn.recv(1024).decode(ENC).strip()
        if password == PASSWORD:
            conn.sendall("AUTH_SUCCESS".encode(ENC))
            print(f"[+] Client authenticated successfully.")
            return True
        else:
            conn.sendall("AUTH_FAIL".encode(ENC))
            print(f"[!] Client failed authentication.")
            return False
    else:
        # Client waits for server prompt first
        prompt = conn.recv(1024).decode(ENC)
        if prompt.strip() == "PASSWORD:":
            username = input("Enter username: ")  # just for display, not sent
            pwd = input("Enter password: ")
            conn.sendall(pwd.encode(ENC))
            result = conn.recv(1024).decode(ENC)
            if result == "AUTH_SUCCESS":
                print("[+] Authenticated successfully! You can now chat.")
                return True
            else:
                print("[!] Authentication failed. Exiting.")
                return False
        else:
            print("[!] Unexpected server response.")
            return False


# Run server
def run_server(port, bind_host="0.0.0.0"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_host, port))
    s.listen(1)
    print(f"[+] Server listening on {bind_host}:{port}")
    conn, addr = s.accept()
    print(f"[+] Connection from {addr[0]}:{addr[1]}")

    if not authenticate(conn, "server"):
        conn.close()
        s.close()
        return

    t_recv = threading.Thread(target=recv_loop, args=(conn, f"{addr[0]}"), daemon=True)
    t_send = threading.Thread(target=send_loop, args=(conn, f"{addr[0]}"), daemon=True)
    t_recv.start(); t_send.start()
    t_send.join()

    try:
        conn.close()
    except: pass
    s.close()
    print("[*] Server shutting down.")

# Run client
def run_client(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[+] Connecting to {host}:{port} ...")
    s.connect((host, port))
    if not authenticate(s, "client"):
        s.close()
        return
    print("[+] Chat started. Type '/exit' to quit.")
    t_recv = threading.Thread(target=recv_loop, args=(s, f"{host}"), daemon=True)
    t_send = threading.Thread(target=send_loop, args=(s, f"{host}"), daemon=True)
    t_recv.start(); t_send.start()
    t_send.join()

    try:
        s.close()
    except: pass
    print("[*] Client exiting.")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Two-terminal chat with mandatory password")
    parser.add_argument("--mode", choices=("server","client"), required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    if args.mode == "server":
        run_server(args.port)
    else:
        run_client(args.host, args.port)

if __name__ == "__main__":
    main()
