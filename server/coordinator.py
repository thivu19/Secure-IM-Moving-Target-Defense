"""
    File: server/coordinator.py 

    Description: 
    - user table, availability, and chat setup.
    - Holds all the server's in-memory state (no database needed). Thread-safe:
        every method that touches shared dicts takes the lock. Each connected client
        has one ClientHandle; the coordinator pairs clients up for chats and tracks
        their state.
    - Covers functional requirements 3.1 (multi-client state) and 3.2 (discovery +
        chat establishment).
"""
import threading

from common.state import State


class ClientHandle:
    """What the server knows about one connected client."""
    def __init__(self, user, conn, host, p2p_port):
        self.user = user
        self.conn = conn            # the client-server socket
        self.host = host            # where its direct-chat listener lives
        self.p2p_port = p2p_port
        self.state = State.READY
        self.peer = None            # username of current/pending peer
        self.session_id = None


class Coordinator:
    def __init__(self):
        self._clients = {}          # user -> ClientHandle
        self._lock = threading.Lock()
        self._next_session = 1

    # ---- connection lifecycle ----
    def add(self, handle: ClientHandle) -> bool:
        with self._lock:
            if handle.user in self._clients:
                return False        # name already online
            self._clients[handle.user] = handle
            return True

    def remove(self, user: str):
        with self._lock:
            h = self._clients.pop(user, None)
            # If they were chatting, free the peer.
            if h and h.peer and h.peer in self._clients:
                peer = self._clients[h.peer]
                if peer.peer == user:
                    peer.state = State.READY
                    peer.peer = None
                    peer.session_id = None

    def get(self, user: str):
        with self._lock:
            return self._clients.get(user)

    # ---- discovery ----
    def available_users(self, excluding: str):
        with self._lock:
            return [u for u, h in self._clients.items()
                    if u != excluding and h.state is State.READY]

    # ---- chat setup ----
    def start_invite(self, frm: str, to: str):
        """Mark both parties PENDING if both are free. Returns status string."""
        with self._lock:
            if frm == to:
                return "self"               # can't chat with yourself
            a = self._clients.get(frm)
            b = self._clients.get(to)
            if not b:
                return "no_such_user"
            if a.state is not State.READY or b.state is not State.READY:
                return "busy"
            a.state = b.state = State.PENDING
            a.peer, b.peer = to, frm
            return "ok"

    def confirm_session(self, frm: str, to: str):
        """Both accepted: assign one session id, move both to CHATTING.

        Returns (session_id, handle_a, handle_b) or None.
        """
        with self._lock:
            a = self._clients.get(frm)
            b = self._clients.get(to)
            if not (a and b):
                return None
            sid = f"S{self._next_session}"
            self._next_session += 1
            a.session_id = b.session_id = sid
            a.state = b.state = State.CHATTING
            return sid, a, b

    def cancel(self, frm: str, to: str):
        """Invite declined/cancelled: both back to READY."""
        with self._lock:
            for u in (frm, to):
                h = self._clients.get(u)
                if h:
                    h.state = State.READY
                    h.peer = None
                    h.session_id = None
