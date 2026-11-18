"""
    File: client/chat.py 

    Description:
    - direct client-to-client chat (requirement 3.3).
    - After the server hands out SESSION_START, the two clients talk DIRECTLY here
        nothing goes back through the server. One side listens (responder), the other
        connects (initiator); the server told each which role it has.
    - A background thread prints incoming messages so the user can type and receive
        at the same time. When the chat ends (CHAT_END or a dropped connection), the
        on_close callback lets the client reset itself to READY.

    FOR LATER STAGES:
    - SECURE HOOK (Section 4): once the signed-DH handshake runs over this socket,
        wrap it in a SecureChannel and seal()/open() every CHAT_MSG instead of plaintext.
    - MTD HOOK (Section 5): the listener socket here is what migration replaces.
"""
import socket
import threading

import settings
from common import messages as M
from common.framing import send_msg, recv_msg


class ChatConnection:
    def __init__(self, session_id, me, peer):
        self.session_id = session_id
        self.me = me
        self.peer = peer
        self.sock = None
        self.alive = False
        self._on_message = None
        self._on_close = None

    # ---- establishing the direct link ----
    def listen_and_accept(self, bind_host, bind_port):
        """Responder side: wait for the initiator to connect."""
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind((bind_host, bind_port))
        lsock.listen(1)
        self.sock, _ = lsock.accept()
        lsock.close()
        # SECURE (Section 4): run peer handshake here, then build SecureChannel.
        self.alive = True

    def connect(self, host, port):
        """Initiator side: dial the responder's listener."""
        self.sock = socket.create_connection((host, port))
        # SECURE (Section 4): run peer handshake here, then build SecureChannel.
        self.alive = True

    # ---- messaging ----
    def start_receiver(self, on_message, on_close=None):
        self._on_message = on_message
        self._on_close = on_close
        threading.Thread(target=self._recv_loop, daemon=True).start()

    def _recv_loop(self):
        try:
            while self.alive:
                msg = M.decode(recv_msg(self.sock))
                # SECURE (Section 4): open() the frame here to verify + decrypt.
                if msg.get("type") == M.CHAT_END:
                    self._on_message(f"[{self.peer} ended the chat]")
                    break
                elif msg.get("type") == M.CHAT_MSG:
                    self._on_message(f"{self.peer}: {msg.get('text', '')}")
        except (ConnectionError, ValueError, OSError):
            if self.alive:
                self._on_message(f"[connection to {self.peer} lost]")
        finally:
            self.alive = False
            if self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass
            if self._on_close:
                self._on_close()

    def send_text(self, text):
        # SECURE (Section 4): seal() instead of sending plaintext.
        send_msg(self.sock, M.encode({"type": M.CHAT_MSG,
                                      "session_id": self.session_id,
                                      "text": text}))

    def end(self):
        if self.alive:
            try:
                send_msg(self.sock, M.encode({"type": M.CHAT_END,
                                              "session_id": self.session_id}))
                self.sock.shutdown(socket.SHUT_WR)   # flush CHAT_END before close
            except OSError:
                pass
        self.alive = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


def pick_p2p_port():
    """A listening port for this client's direct chats."""
    import random
    return random.randint(settings.P2P_PORT_MIN, settings.P2P_PORT_MAX)
