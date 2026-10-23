"""
    File: client/client.py

    Description:
    - the command-line client.
    - Functional (unsecured) version (Section 3). Connects to the server, logs in by name, and
        gives you a prompt:

            /list              show available users
            /chat <user>       invite someone
            /accept <user>     accept an invite
            /decline <user>    decline an invite
            /msg <text>        send a message in the current chat
            /end               end the current chat
            /quit              log out and exit

    - A background thread listens to the server so invites/session notices arrive
        while you're typing.

    FOR LATER STAGES:
    - SECURE HOOK (Section 4): replace login with the signed challenge-response;
        wrap the server socket in a SecureChannel.
"""
import socket
import sys
import threading
import time

import settings
from common import messages as M
from common.framing import send_msg, recv_msg
from common.state import State
from client.chat import ChatConnection, pick_p2p_port


class Client:
    def __init__(self, user):
        self.user = user
        self.sock = None
        self.state = State.READY
        self.p2p_port = pick_p2p_port()
        self.pending_from = None     # who invited me / who I invited
        self.chat_conn = None        # active ChatConnection

    # ---- server I/O ----
    def send(self, obj):
        send_msg(self.sock, M.encode(obj))

    def connect(self):
        self.sock = socket.create_connection(
            (settings.SERVER_HOST, settings.SERVER_PORT))
        # SECURE (Section 4): challenge-response instead of a plain hello.
        self.send({"type": M.LOGIN_HELLO, "user": self.user,
                   "p2p_port": self.p2p_port})
        reply = M.decode(recv_msg(self.sock))
        if reply.get("type") != M.LOGIN_OK:
            print("Login failed:", reply.get("reason"))
            sys.exit(1)
        print(f"Logged in as {self.user}. Type /help for commands.")
        threading.Thread(target=self._server_loop, daemon=True).start()

    def _server_loop(self):
        try:
            while True:
                msg = M.decode(recv_msg(self.sock))
                self._handle_server(msg)
        except (ConnectionError, ValueError, OSError):
            print("\n[disconnected from server]")

    def _handle_server(self, msg):
        t = msg.get("type")
        if t == M.USER_LIST:
            print("\nAvailable:", ", ".join(msg["users"]) or "(nobody)")
        elif t == M.INVITE:
            self.pending_from = msg["from"]
            self.state = State.PENDING
            print(f"\n{msg['from']} wants to chat. /accept {msg['from']} "
                  f"or /decline {msg['from']}")
        elif t == M.BUSY:
            print(f"\n{msg['peer']} is busy.")
            self.state = State.READY
        elif t == M.SESSION_START:
            self._start_chat(msg)
        elif t == M.ERROR:
            print("\nServer:", msg["reason"])
            self.state = State.READY

    # ---- chat setup ----
    def _start_chat(self, msg):
        sid, peer = msg["session_id"], msg["peer"]
        self.chat_conn = ChatConnection(sid, self.user, peer)
        if msg["role"] == "responder":
            def wait():
                self.chat_conn.listen_and_accept(settings.SERVER_HOST,
                                                 self.p2p_port)
                self.chat_conn.start_receiver(self._print_incoming,
                                              self._on_chat_closed)
                print(f"\n[connected with {peer}, session {sid}]")
            threading.Thread(target=wait, daemon=True).start()
        else:
            def dial():
                for _ in range(10):
                    try:
                        self.chat_conn.connect(msg["peer_host"], msg["peer_port"])
                        break
                    except (ConnectionRefusedError, OSError):
                        time.sleep(0.2)
                else:
                    print(f"\n[could not reach {peer}]\n> ", end="")
                    self.state = State.READY
                    self.chat_conn = None
                    return
                self.chat_conn.start_receiver(self._print_incoming,
                                              self._on_chat_closed)
                print(f"\n[connected with {peer}, session {sid}]\n> ", end="")
            threading.Thread(target=dial, daemon=True).start()
        self.state = State.CHATTING

    def _print_incoming(self, line):
        print("\n" + line + "\n> ", end="")

    def _on_chat_closed(self):
        """Called when the peer ends the chat or the connection drops."""
        self.state = State.READY
        self.chat_conn = None
        self.pending_from = None
        # Tell the server we're free again (chat end is peer-to-peer, so the
        # server doesn't know otherwise). Harmless if sent more than once.
        try:
            self.send({"type": M.END_SESSION})
        except OSError:
            pass
        print("\n[back to READY — you can /list or /chat again]\n> ", end="")

    # ---- command handling ----
    def repl(self):
        while True:
            try:
                line = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                line = "/quit"
            if not line:
                continue

            if line == "/help":
                print("/list  /chat <u>  /accept <u>  /decline <u>  "
                      "/msg <text>  /end  /quit")

            elif line == "/list":
                self.send({"type": M.LIST})

            elif line.startswith("/chat "):
                peer = line.split(None, 1)[1].strip()
                if not peer:
                    print("Usage: /chat <user>")
                elif peer == self.user:
                    print("You can't chat with yourself.")
                elif self.state is not State.READY:
                    print("You're already in a chat or have a pending invite.")
                else:
                    self.send({"type": M.REQUEST, "peer": peer})
                    self.state = State.PENDING

            elif line.startswith("/accept "):
                frm = line.split(None, 1)[1].strip()
                if frm and frm == self.pending_from:
                    self.send({"type": M.ACCEPT, "from": frm})
                else:
                    print("No pending invite from that user.")

            elif line.startswith("/decline "):
                frm = line.split(None, 1)[1].strip()
                if frm:
                    self.send({"type": M.DECLINE, "from": frm})
                    self.pending_from = None
                    self.state = State.READY

            elif line.startswith("/msg "):
                text = line.split(None, 1)[1].strip()
                if not text:
                    print("Usage: /msg <text>")
                elif self.chat_conn and self.chat_conn.alive:
                    self.chat_conn.send_text(text)
                else:
                    print("No active chat.")

            elif line == "/end":
                if self.chat_conn:
                    self.chat_conn.end()
                    self.state = State.READY
                    self.chat_conn = None
                    print("[chat ended]")
                else:
                    print("No active chat.")

            elif line == "/quit":
                if self.chat_conn:
                    self.chat_conn.end()
                try:
                    self.send({"type": M.LOGOUT})
                except OSError:
                    pass
                break

            else:
                print("Unknown command. /help for list.")


def main(user=None):
    user = user or (sys.argv[1] if len(sys.argv) > 1 else input("Username: "))
    c = Client(user)
    c.connect()
    c.repl()


if __name__ == "__main__":
    main()
