"""
    File: server/server.py
    
    Description:
    - Accept loop + per-client dispatch. One thread per client; LIST /
      REQUEST / ACCEPT / DECLINE; hands both clients a session id + the
      peer's direct endpoint.
    - SECURE: login is a signed challenge-response (server/auth.py),
      and the whole client-server command loop is SEALED with a per-client
      SecureChannel -- confidentiality, integrity, freshness.
    - The server never relays chat content; once a chat starts the two clients
      talk directly.

    Note: each client has its OWN channel, so a message the server sends to a peer
    (INVITE, SESSION_START, ...) is sealed with THAT peer's channel.

    Section 5 (MTD): migration is entirely client-to-client -- the server is NOT
    involved once a session has started, so nothing changes here for Section 5.
"""
import glob
import os
import socket
import threading

import settings
from common import messages as M
from common.framing import send_msg, recv_msg
from common.secure_channel import SecureChannel, SecurityError
from server.coordinator import Coordinator, ClientHandle
from server.auth import server_authenticate, load_public_keys

coordinator = Coordinator()


def _known_users():
    """Everyone with a public key in keys/ -- so the server can verify their login."""
    return [os.path.basename(p)[:-len("_public.pem")]
            for p in glob.glob(os.path.join(settings.KEYS_DIR, "*_public.pem"))]


PUBKEYS = load_public_keys(_known_users(), settings.KEYS_DIR)   # loaded once at startup


def send(conn, obj):
    """Plaintext send -- used only for the pre-channel LOGIN_OK / LOGIN_FAIL."""
    send_msg(conn, M.encode(obj))


def seal_send(handle, obj):
    """Sealed send to one client, using THAT client's channel."""
    with handle.send_lock:
        send_msg(handle.conn, M.encode(handle.chan.seal(M.encode(obj))))


def sealed_recv(handle):
    """Open the next sealed message from this client -> dict."""
    return M.decode(handle.chan.open(M.decode(recv_msg(handle.conn))))


def handle_client(conn, addr):
    user = None
    try:
        # No idle timeout: during a chat this control socket is legitimately silent
        # (traffic goes directly between the two clients).

        # SECURE: signed challenge-response login (Section 4.2)
        user, secret, p2p_port = server_authenticate(conn, PUBKEYS)
        handle = ClientHandle(user, conn, addr[0], p2p_port)
        handle.authenticated = True
        if not coordinator.add(handle):
            send(conn, {"type": M.LOGIN_FAIL, "reason": "name in use"})
            return

        # client-server channel: the server is the responder side here
        handle.chan = SecureChannel(secret, "cs:" + user, is_initiator=False, me="server")
        send(conn, {"type": M.LOGIN_OK, "user": user})       # plaintext (pre-channel)
        if settings.DEBUG:
            print(f"[secure] verified {user}'s RSA signature; client-server channel sealed")
        print(f"[+] {user} online from {addr[0]} (p2p port {p2p_port})")

        # ---- Command loop (every message sealed) ----
        while True:
            msg = sealed_recv(handle)
            t = msg.get("type")

            if t == M.LIST:
                seal_send(handle, {"type": M.USER_LIST,
                                   "users": coordinator.available_users(user)})

            elif t == M.REQUEST:
                peer = msg["peer"]
                status = coordinator.start_invite(user, peer)
                if status == "ok":
                    ph = coordinator.get(peer)
                    seal_send(ph, {"type": M.INVITE, "from": user})   # peer's channel
                elif status == "busy":
                    seal_send(handle, {"type": M.BUSY, "peer": peer})
                elif status == "self":
                    seal_send(handle, {"type": M.ERROR,
                                       "reason": "cannot chat with yourself"})
                else:
                    seal_send(handle, {"type": M.ERROR, "reason": "no such user"})

            elif t == M.ACCEPT:
                frm = msg["from"]                                   # the inviter
                result = coordinator.confirm_session(frm, user)
                if result:
                    sid, a, b = result
                    # give each side the peer's endpoint + its role
                    seal_send(a, {"type": M.SESSION_START, "session_id": sid,
                                  "peer": b.user, "peer_host": b.host,
                                  "peer_port": b.p2p_port, "role": "initiator"})
                    seal_send(b, {"type": M.SESSION_START, "session_id": sid,
                                  "peer": a.user, "peer_host": a.host,
                                  "peer_port": a.p2p_port, "role": "responder"})
                    print(f"[=] session {sid}: {a.user} <-> {b.user}")

            elif t == M.DECLINE:
                frm = msg["from"]
                coordinator.cancel(frm, user)
                fh = coordinator.get(frm)
                if fh:
                    seal_send(fh, {"type": M.ERROR, "reason": f"{user} declined"})

            elif t == M.END_SESSION:
                me = coordinator.get(user)
                peer = me.peer if me else None
                coordinator.cancel(user, peer)

            elif t == M.LOGOUT:
                break

            else:
                seal_send(handle, {"type": M.ERROR, "reason": f"unknown type {t}"})

    except (ConnectionError, ValueError, KeyError, SecurityError, socket.timeout) as e:
        print(f"[-] {user or addr} dropped: {e}")
    except Exception as e:
        # auth failures / malformed clients: log and close, don't crash the thread
        print(f"[-] {user or addr} rejected: {e}")
    finally:
        if user:
            coordinator.remove(user)
            print(f"[-] {user} offline")
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((settings.SERVER_HOST, settings.SERVER_PORT))
    srv.listen()
    srv.settimeout(1.0)          # wake each second so Ctrl+C is noticed
    print(f"Server on {settings.SERVER_HOST}:{settings.SERVER_PORT}")
    try:
        while True:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nShutting down server.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
