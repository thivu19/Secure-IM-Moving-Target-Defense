"""
    File: client/chat.py
    
    Description:
    - Direct client-to-client chat, secured.
    - After SESSION_START the two clients talk DIRECTLY here; nothing goes back
      through the server. One side listens (responder), the other connects
      (initiator) -- the server told each which role it has.
    - SECURE: once the direct socket is up, both sides run an
      authenticated DH handshake, then every message is sealed/opened through a
      SecureChannel. The key is wiped when the chat ends.

    MTD HOOK (Section 5): the listener socket created here is the stable endpoint
    that migration moves. A migration opens a NEW listener on a new random port and
    re-points the peer there, REUSING this same SecureChannel (keys + sequence
    numbers carry over), so the conversation continues as one logical session.
"""
import socket
import threading

import settings
from common import messages as M
from common.framing import send_msg, recv_msg
from common.secure_channel import SecureChannel, SecurityError
from client.handshake import peer_handshake


class ChatConnection:
    def __init__(self, session_id, me, peer, role, my_private_key, peer_public_key):
        self.session_id = session_id
        self.me = me
        self.peer = peer
        self.role = role                      # "initiator" or "responder" (from server)
        self.my_private_key = my_private_key
        self.peer_public_key = peer_public_key
        self.sock = None
        self.alive = False
        self.chan = None                      # SecureChannel once the handshake completes
        self._on_message = None
        self._on_close = None

    # ---- establishing the direct link ----
    def listen_and_accept(self, bind_host, bind_port):
        """Responder side: wait for the initiator to connect, then handshake.

        MTD HOOK (Section 5): migration re-runs this on a NEW random port.
        """
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind((bind_host, bind_port))
        lsock.listen(1)
        self.sock, _ = lsock.accept()
        lsock.close()
        self._do_handshake()                  # SECURE
        self.alive = True

    def connect(self, host, port):
        """Initiator side: dial the responder's listener, then handshake."""
        self.sock = socket.create_connection((host, port))
        self._do_handshake()                  # SECURE
        self.alive = True

    def _do_handshake(self):
        """Authenticated DH with the peer, then build the per-session SecureChannel."""
        secret = peer_handshake(
            self.sock, self.me, self.peer, self.session_id,
            is_initiator=(self.role == "initiator"),
            my_private_key=self.my_private_key,
            peer_public_key=self.peer_public_key,
        )
        self.chan = SecureChannel(
            secret, self.session_id,
            is_initiator=(self.role == "initiator"), me=self.me,
        )
        if settings.DEBUG:
            print(f"\n[secure] authenticated key exchange with {self.peer} done -- "
                  f"session key derived directly (server never saw it)")

    # ---- messaging ----
    def start_receiver(self, on_message, on_close=None):
        self._on_message = on_message
        self._on_close = on_close
        threading.Thread(target=self._recv_loop, daemon=True).start()

    def _recv_loop(self):
        try:
            while self.alive:
                raw = M.decode(recv_msg(self.sock))
                try:
                    inner = self.chan.open(raw)          # verify + decrypt
                except SecurityError:
                    if settings.DEBUG:
                        self._on_message("[secure] dropped a message that failed "
                                         "its integrity/freshness check")
                    continue                             # reject, don't disconnect
                msg = M.decode(inner)
                t = msg.get("type")
                # MTD HOOK (Section 5): a MIGRATE message would be handled here.
                if t == M.CHAT_END:
                    self._on_message(f"[{self.peer} ended the chat]")
                    break
                elif t == M.CHAT_MSG:
                    self._on_message(f"{self.peer}: {msg.get('text', '')}")
        except (ConnectionError, ValueError, OSError):
            if self.alive:
                self._on_message(f"[connection to {self.peer} lost]")
        finally:
            self.alive = False
            self.chan = None                             # key erasure
            if self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass
            if self._on_close:
                self._on_close()

    def send_text(self, text):
        """Seal the whole message object (so its type survives) and send it."""
        inner = M.encode({"type": M.CHAT_MSG, "text": text})
        sealed = self.chan.seal(inner)
        if settings.DEBUG:
            print(f"[wire] ct={sealed['ct'][:24]}... tag={sealed['tag'][:16]}...")
        send_msg(self.sock, M.encode(sealed))

    def end(self):
        if self.alive and self.chan:
            try:
                inner = M.encode({"type": M.CHAT_END})
                send_msg(self.sock, M.encode(self.chan.seal(inner)))
                self.sock.shutdown(socket.SHUT_WR)       # flush CHAT_END before close
            except OSError:
                pass
        self.alive = False
        self.chan = None                                 # key erasure on chat end
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    # MTD HOOK (Section 5): add migrate()/handle_migrate() here. They pick a new
    # random port, swap sockets, and KEEP self.chan unchanged so the session continues.


def pick_p2p_port():
    """A listening port for this client's direct chats."""
    import random
    return random.randint(settings.P2P_PORT_MIN, settings.P2P_PORT_MAX)
