"""
    File: server/server.py — 

    Description:
    - accept loop + per-client dispatch.
    - Functional (unsecured) version (Section 3)
    - It handles:
        - multiple clients, one thread each   (3.1)
        - login by name                       (FOR LATER STAGES: becomes signed auth in Section 4)
        - LIST / REQUEST / ACCEPT / DECLINE   (3.2)
        - handing both clients a session id + the peer's direct endpoint (3.2/3.3)

    FOR LATER STAGES:
    - SECURE HOOK (Section 4): where marked "SECURE:", wrap recv/send with the login
        handshake and a SecureChannel. The functional logic below does not change.
"""
import socket
import threading

import settings
from common import messages as M
from common.framing import send_msg, recv_msg
from server.coordinator import Coordinator, ClientHandle

coordinator = Coordinator()


def send(conn, obj):
    send_msg(conn, M.encode(obj))


def recv(conn):
    return M.decode(recv_msg(conn))


def handle_client(conn, addr):
    user = None
    try:
        # NOTE: no idle timeout here. During a chat, all traffic goes directly
        # between the two clients, so this control socket is legitimately silent.
        # A timeout would drop active chatters. (FOR LATER STAGES: add keepalives.)

        # Login (FOR LATER STAGES - SECURE: replace with challenge/response in Section 4)
        hello = recv(conn)
        if hello.get("type") != M.LOGIN_HELLO:
            send(conn, {"type": M.LOGIN_FAIL, "reason": "expected LOGIN_HELLO"})
            return
        user = hello["user"]
        p2p_port = hello.get("p2p_port", 0)
        handle = ClientHandle(user, conn, addr[0], p2p_port)
        if not coordinator.add(handle):
            send(conn, {"type": M.LOGIN_FAIL, "reason": "name in use"})
            return
        send(conn, {"type": M.LOGIN_OK, "user": user})
        print(f"[+] {user} online from {addr[0]} (p2p port {p2p_port})")

        # ---- Command loop ----
        while True:
            msg = recv(conn)
            t = msg.get("type")

            if t == M.LIST:
                send(conn, {"type": M.USER_LIST,
                            "users": coordinator.available_users(user)})

            elif t == M.REQUEST:
                peer = msg["peer"]
                status = coordinator.start_invite(user, peer)
                if status == "ok":
                    ph = coordinator.get(peer)
                    send(ph.conn, {"type": M.INVITE, "from": user})
                elif status == "busy":
                    send(conn, {"type": M.BUSY, "peer": peer})
                elif status == "self":
                    send(conn, {"type": M.ERROR,
                                "reason": "cannot chat with yourself"})
                else:
                    send(conn, {"type": M.ERROR, "reason": "no such user"})

            elif t == M.ACCEPT:
                frm = msg["from"]           # the inviter
                result = coordinator.confirm_session(frm, user)
                if result:
                    sid, a, b = result
                    send(a.conn, {"type": M.SESSION_START, "session_id": sid,
                                  "peer": b.user, "peer_host": b.host,
                                  "peer_port": b.p2p_port, "role": "initiator"})
                    send(b.conn, {"type": M.SESSION_START, "session_id": sid,
                                  "peer": a.user, "peer_host": a.host,
                                  "peer_port": a.p2p_port, "role": "responder"})
                    print(f"[=] session {sid}: {a.user} <-> {b.user}")

            elif t == M.DECLINE:
                frm = msg["from"]
                coordinator.cancel(frm, user)
                fh = coordinator.get(frm)
                if fh:
                    send(fh.conn, {"type": M.ERROR, "reason": f"{user} declined"})

            elif t == M.END_SESSION:
                me = coordinator.get(user)
                peer = me.peer if me else None
                coordinator.cancel(user, peer)

            elif t == M.LOGOUT:
                break

            else:
                send(conn, {"type": M.ERROR, "reason": f"unknown type {t}"})

    except (ConnectionError, ValueError, KeyError, socket.timeout) as e:
        print(f"[-] {user or addr} dropped: {e}")
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
    srv.settimeout(1.0)          # wake up each second so Ctrl+C is noticed
    print(f"Server on {settings.SERVER_HOST}:{settings.SERVER_PORT}")
    try:
        while True:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle_client, args=(conn, addr),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\nShutting down server.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
    