"""
    File: client/client.py

    Description:
    - The command-line client, secured.
    - Connects to the server, logs in with a signed challenge-response, and wraps
      the server socket in a SecureChannel so the whole control conversation
      (list / invite / accept / ...) is confidential, authenticated, and fresh.
    - A background thread listens to the server so invites / session notices arrive
      while you're typing. The direct chat runs its own handshake + SecureChannel
      (see client/chat.py).

    Once logged in, it gives you a prompt:

        /list              show available users
        /chat <user>       request a chat with a user
        /accept <user>     accept an incoming invite
        /decline <user>    decline an incoming invite
        /msg <text>        send a message in the current chat
        /end               end the current chat
        /quit              log out and exit
        /help              show this list

    MTD HOOK (Section 5): a /migrate command would be added in repl() below.
"""
import os
import socket
import sys
import threading
import time

import settings
from common import messages as M
from common.framing import send_msg, recv_msg
from common.state import State
from common import crypto
from common.secure_channel import SecureChannel, SecurityError
from client.auth import client_login
from client.chat import ChatConnection, pick_p2p_port


class Client:
    def __init__(self, user, key_user=None):
        self.user = user
        self.sock = None
        self.state = State.READY
        self.p2p_port = pick_p2p_port()
        self.pending_from = None            # who invited me / who I invited
        self.chat_conn = None               # active ChatConnection
        self.cs_chan = None                 # client-server SecureChannel (after login)
        # our long-term RSA private key, used to sign login + peer handshakes.
        # key_user lets the demo sign with SOMEONE ELSE's key (impersonation) --
        # the server should reject that login.
        signer = key_user or user
        self.my_private_key = crypto.load_private_key(
            os.path.join(settings.KEYS_DIR, f"{signer}_private.pem"))
        if key_user and key_user != user:
            print(f"[demo] claiming to be '{user}' but signing with {key_user}'s key "
                  "-- the server should REJECT this login")

    # ---- server I/O (sealed once logged in) ----
    def send(self, obj):
        send_msg(self.sock, M.encode(self.cs_chan.seal(M.encode(obj))))

    def connect(self):
        self.sock = socket.create_connection(
            (settings.SERVER_HOST, settings.SERVER_PORT))
        # SECURE: signed challenge-response instead of a plain hello
        try:
            secret = client_login(self.sock, self.user,
                                  self.my_private_key, self.p2p_port)
        except Exception as e:
            print("Login failed:", e)
            sys.exit(1)
        # client is the initiator side of the client-server channel
        self.cs_chan = SecureChannel(secret, "cs:" + self.user,
                                     is_initiator=True, me=self.user)
        if settings.DEBUG:
            print("[secure] signed login OK -- encrypted channel to server established")
        print("=" * 46)
        print(f"  Secure IM   |   logged in as {self.user}")
        print("=" * 46)
        print("Type /help to see the commands.")
        threading.Thread(target=self._server_loop, daemon=True).start()

    def _server_loop(self):
        try:
            while True:
                raw = M.decode(recv_msg(self.sock))
                msg = M.decode(self.cs_chan.open(raw))      # verify + decrypt
                self._handle_server(msg)
        except (ConnectionError, ValueError, OSError):
            print("\n[disconnected from server]")
        except SecurityError:
            print("\n[server message failed a security check]")

    def _handle_server(self, msg):
        t = msg.get("type")
        if t == M.USER_LIST:
            users = msg["users"]
            if users:
                print("\nAvailable users:", ", ".join(users))
            else:
                print("\nAvailable users: (no one else online)")
        elif t == M.INVITE:
            self.pending_from = msg["from"]
            self.state = State.PENDING
            print(f"\n{msg['from']} wants to chat. "
                  f"/accept {msg['from']} or /decline {msg['from']}")
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
        sid, peer, role = msg["session_id"], msg["peer"], msg["role"]
        # load the peer's public key so the handshake can authenticate them
        peer_pub = crypto.load_public_key(
            os.path.join(settings.KEYS_DIR, f"{peer}_public.pem"))
        self.chat_conn = ChatConnection(sid, self.user, peer, role,
                                        self.my_private_key, peer_pub)
        if role == "responder":
            def wait():
                self.chat_conn.listen_and_accept(settings.SERVER_HOST, self.p2p_port)
                self.chat_conn.start_receiver(self._print_incoming, self._on_chat_closed)
                print(f"\n--- connected with {peer}  (session {sid}) ---")
            threading.Thread(target=wait, daemon=True).start()
        else:
            def dial():
                for _ in range(10):                 # responder may still be setting up
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
                self.chat_conn.start_receiver(self._print_incoming, self._on_chat_closed)
                print(f"\n--- connected with {peer}  (session {sid}) ---\n> ", end="")
            threading.Thread(target=dial, daemon=True).start()
        self.state = State.CHATTING

    def _print_incoming(self, line):
        print("\n" + line + "\n> ", end="")

    def _on_chat_closed(self):
        """Called when the peer ends the chat or the connection drops."""
        self.state = State.READY
        self.chat_conn = None
        self.pending_from = None
        # chat end is peer-to-peer, so tell the server we're free again
        try:
            self.send({"type": M.END_SESSION})
        except OSError:
            pass
        print("\n[back to READY - you can /list or /chat again]\n> ", end="")

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
                print("\nCommands:")
                print("  /list              show available users")
                print("  /chat <user>       request a chat with a user")
                print("  /accept <user>     accept an incoming invite")
                print("  /decline <user>    decline an incoming invite")
                print("  /msg <text>        send a message in the current chat")
                print("  /end               end the current chat")
                print("  /quit              log out and exit")
                print("  /help              show this list\n")

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
                if self.state is State.PENDING and frm and frm == self.pending_from:
                    self.send({"type": M.ACCEPT, "from": frm})
                    self.pending_from = None
                else:
                    print("No pending invite from that user.")

            elif line.startswith("/decline "):
                frm = line.split(None, 1)[1].strip()
                if self.state is State.PENDING and frm and frm == self.pending_from:
                    self.send({"type": M.DECLINE, "from": frm})
                    self.pending_from = None
                    self.state = State.READY
                else:
                    print("No pending invite from that user.")

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

            # MTD HOOK (Section 5): add a manual trigger for the demo, e.g.
            # elif line == "/migrate":
            #     if self.chat_conn and self.chat_conn.alive:
            #         self.chat_conn.migrate()
            #     else:
            #         print("No active chat to migrate.")

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


def main(user=None, key_user=None):
    user = user or (sys.argv[1] if len(sys.argv) > 1 else input("Username: "))
    c = Client(user, key_user)
    c.connect()
    c.repl()


if __name__ == "__main__":
    main()
