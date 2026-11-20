"""
    File: client/auth.py — client side of login.

    Description:
    - The signed challenge-response:
        client -> LOGIN_HELLO    {user, p2p_port, dh_pub, nonce}
        server -> LOGIN_CHALLENGE{server_nonce, dh_pub}
        client -> LOGIN_PROVE    {signature over the transcript}
        server -> LOGIN_OK / LOGIN_FAIL
    - On success both sides share a client-server secret (DH). The transcript
      (identity + both DH values + both nonces) is what gets signed, so a recorded
      login can't be replayed as a different exchange.
"""
from common import messages as M
from common.framing import send_msg, recv_msg
from common import crypto


def client_login(sock, user, my_private_key, p2p_port=0):
    """Returns the client-server shared secret (bytes) on success; raises on failure.
    p2p_port is sent so the server can tell a peer where to reach us for direct chat."""
    # our ephemeral DH value + a fresh nonce
    my_dh_priv, my_dh_pub = crypto.dh_keypair()
    my_nonce = crypto.gen_nonce()
    send_msg(sock, M.encode({"type": M.LOGIN_HELLO, "user": user, "p2p_port": p2p_port,
                             "dh_pub": my_dh_pub, "nonce": my_nonce.hex()}))

    chal = M.decode(recv_msg(sock))
    if chal.get("type") != M.LOGIN_CHALLENGE:
        raise Exception("expected LOGIN_CHALLENGE, got " + str(chal.get("type")))
    server_pub = chal["dh_pub"]
    server_nonce = chal["server_nonce"]

    # Sign the full transcript with our RSA private key (signing only, never encryption).
    # It binds our identity + BOTH DH publics + BOTH nonces. Because the server's
    # fresh nonce is inside what we sign, a recorded login can't be replayed to log
    # in again later (4.2). The server rebuilds this exact string to verify.
    transcript = f"{user}|{my_dh_pub}|{server_pub}|{my_nonce.hex()}|{server_nonce}".encode()
    sig = crypto.sign(my_private_key, transcript)
    send_msg(sock, M.encode({"type": M.LOGIN_PROVE, "signature": sig.hex()}))

    reply = M.decode(recv_msg(sock))
    if reply.get("type") != M.LOGIN_OK:
        raise Exception("login failed: " + str(reply.get("reason")))

    # both sides derive the same client-server secret
    return crypto.dh_shared(server_pub, my_dh_priv)
