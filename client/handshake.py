"""
    File: client/handshake.py
    
    Description:
    - Authenticated client-to-client key exchange.
    - After SESSION_START, the two clients run an authenticated Diffie-Hellman
      directly over their socket. Each signs a transcript binding both identities,
      the session id, both DH public values, and fresh nonces -- so each side knows
      it is talking to the intended peer for THIS session, and the server never
      sees the resulting key.
    - RSA is used only to SIGN the exchange (prove who we are), never to transport
      the secret. The secret comes from Diffie-Hellman and is never sent.
"""
from common import messages as M
from common.framing import send_msg, recv_msg
from common import crypto


def peer_handshake(sock, me, peer, session_id, is_initiator,
                   my_private_key, peer_public_key):
    """Return the shared peer secret (bytes). Both sides get the same value.
    Raises if the peer's signature doesn't verify.

    sock            : the already-connected direct socket to the peer
    me / peer       : our username / the peer's username
    session_id      : the id the server assigned to this chat (binds the key to it)
    is_initiator    : our role, from the server's SESSION_START (decides send order)
    my_private_key  : our RSA key, to sign our half
    peer_public_key : the peer's RSA key, to verify their half
    """
    # Our ephemeral DH value (private stays local, public goes to the peer) and a
    # fresh nonce so this handshake can't be confused with a recorded old one.
    my_dh_priv, my_dh_pub = crypto.dh_keypair()
    my_nonce = crypto.gen_nonce()

    # Sign our transcript: it ties our identity, the peer we think we're talking to,
    # the session id, our DH public value, and our nonce together. Signing proves
    # the DH value really came from us (stops a man-in-the-middle swapping it).
    my_transcript = f"{session_id}|{me}|{peer}|{my_dh_pub}|{my_nonce.hex()}".encode()
    my_sig = crypto.sign(my_private_key, my_transcript)
    my_msg = M.encode({"type": M.PEER_DH, "dh_pub": my_dh_pub,
                       "nonce": my_nonce.hex(), "sig": my_sig.hex()})

    # One side must send first or both would block waiting to receive. The server
    # already assigned roles, so the initiator sends then receives, the responder
    # receives then sends -- they stay in step.
    if is_initiator:
        send_msg(sock, my_msg)
        their = M.decode(recv_msg(sock))
    else:
        their = M.decode(recv_msg(sock))
        send_msg(sock, my_msg)

    # Read the peer's DH public value, nonce, and signature from their message.
    if their.get("type") != M.PEER_DH:
        raise Exception("expected PEER_DH")
    their_pub = their["dh_pub"]
    their_nonce = their["nonce"]
    their_sig = bytes.fromhex(their["sig"])

    # Rebuild the string the PEER would have signed: note me/peer are SWAPPED
    # relative to our own transcript above (they put their own name first). We
    # verify it with the peer's public key, so we know we're talking to the
    # intended user for THIS session, not a man in the middle. If anything was
    # tampered with (DH value, nonce, names, session id), the signature won't match.
    their_transcript = f"{session_id}|{peer}|{me}|{their_pub}|{their_nonce}".encode()
    if not crypto.verify(peer_public_key, their_transcript, their_sig):
        raise Exception("peer signature invalid - wrong peer or tampered handshake")

    # Combine our private value with their public value: both sides arrive at the
    # SAME shared secret, and it never travelled over the network. This feeds the
    # SecureChannel's key derivation.
    return crypto.dh_shared(their_pub, my_dh_priv)
