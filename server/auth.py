"""
    File: server/auth.py — server side of login + authorization.

    Description:
    - The server verifies the client's signed challenge against the registered
      public key for the claimed identity. No passwords.
    - On success it returns (user, shared_secret, p2p_port). It does NOT send
      LOGIN_OK itself — the caller (server.py) sends that only after the
      name-in-use check passes, so the two steps stay in the right order.

    pubkeys: dict  username -> loaded RSA public key  (loaded once at startup from keys/)
"""
import os

from common import messages as M
from common.framing import send_msg, recv_msg
from common import crypto


def server_authenticate(sock, pubkeys):
    """Run the server side of login.
    Returns (user, shared_secret, p2p_port) on success; raises (and sends
    LOGIN_FAIL) on failure."""
    hello = M.decode(recv_msg(sock))
    if hello.get("type") != M.LOGIN_HELLO:
        send_msg(sock, M.encode({"type": M.LOGIN_FAIL, "reason": "expected LOGIN_HELLO"}))
        raise Exception("bad login start")

    user = hello["user"]
    client_pub = hello["dh_pub"]
    client_nonce = hello["nonce"]
    p2p_port = hello.get("p2p_port", 0)  # where this client listens for direct chats

    # authorization: the claimed identity must be a registered user
    if user not in pubkeys:
        send_msg(sock, M.encode({"type": M.LOGIN_FAIL, "reason": "unknown user"}))
        raise Exception("unknown user " + user)

    # our ephemeral DH value + a fresh challenge nonce
    my_dh_priv, my_dh_pub = crypto.dh_keypair()
    server_nonce = crypto.gen_nonce()
    send_msg(sock, M.encode({"type": M.LOGIN_CHALLENGE,
                             "server_nonce": server_nonce.hex(), "dh_pub": my_dh_pub}))

    prove = M.decode(recv_msg(sock))
    if prove.get("type") != M.LOGIN_PROVE:
        send_msg(sock, M.encode({"type": M.LOGIN_FAIL, "reason": "expected LOGIN_PROVE"}))
        raise Exception("bad login prove")
    sig = bytes.fromhex(prove["signature"])

    # Rebuild the SAME transcript the client signed and check it against the
    # registered public key for the claimed identity. Only the real user holds the
    # matching private key, so a forged signature (or an impersonator) fails here.
    # Must be byte-for-byte identical to the client's string or verification fails.
    transcript = f"{user}|{client_pub}|{my_dh_pub}|{client_nonce}|{server_nonce.hex()}".encode()
    if not crypto.verify(pubkeys[user], transcript, sig):
        send_msg(sock, M.encode({"type": M.LOGIN_FAIL, "reason": "bad signature"}))
        raise Exception("signature verification failed for " + user)

    # LOGIN_OK is sent by the caller, after the name-in-use check.
    secret = crypto.dh_shared(client_pub, my_dh_priv)
    return user, secret, p2p_port


def load_public_keys(users, keys_dir):
    """Load each user's public key. Call once at server startup."""
    return {u: crypto.load_public_key(os.path.join(keys_dir, f"{u}_public.pem"))
            for u in users}
