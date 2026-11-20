"""
    File: common/messages.py
    
    Description:
    - The shared message contract. Every message on the wire is a JSON object with
      a "type" field. These constants are the single source of truth for the type
      names, so the server and client never disagree about spelling.
    - encode()/decode() turn a dict into bytes and back.
"""
import json

# ---- Client -> Server ----
LOGIN_HELLO   = "LOGIN_HELLO"    # {type, user, p2p_port, dh_pub, nonce}   start login
LIST          = "LIST"           # {type}                                  ask who's online
REQUEST       = "REQUEST"        # {type, peer}                            ask to chat with peer
ACCEPT        = "ACCEPT"         # {type, from}                            accept an invite
DECLINE       = "DECLINE"        # {type, from}                            decline an invite
END_SESSION   = "END_SESSION"    # {type}                                  left a chat, free again
LOGOUT        = "LOGOUT"         # {type}                                  log out and disconnect

# ---- Server -> Client ----
LOGIN_OK      = "LOGIN_OK"       # {type, user}                            login succeeded
LOGIN_FAIL    = "LOGIN_FAIL"     # {type, reason}                          login rejected
USER_LIST     = "USER_LIST"      # {type, users:[...]}                     available users
INVITE        = "INVITE"         # {type, from}                            someone wants to chat
SESSION_START = "SESSION_START"  # {type, session_id, peer, peer_host, peer_port, role}  chat approved
BUSY          = "BUSY"           # {type, peer}                            peer not available
ERROR         = "ERROR"          # {type, reason}                          generic error / notice

# ---- Client <-> Client (direct) ----
CHAT_MSG      = "CHAT_MSG"       # {type, session_id, sender, seq, ct, tag}  a chat message (sealed)
CHAT_END      = "CHAT_END"       # {type, session_id}                        end the chat (sealed)

# ---- Authentication (client <-> server) ----
LOGIN_CHALLENGE = "LOGIN_CHALLENGE"  # {type, server_nonce, dh_pub}  Server->Client: fresh challenge
LOGIN_PROVE     = "LOGIN_PROVE"      # {type, signature}             Client->Server: signed transcript

# ---- Client-to-client handshake ----
PEER_DH         = "PEER_DH"          # {type, dh_pub, nonce, sig}    signed DH value for the peer

# FOR LATER STAGE: adjust as needed
# ---- Section 5: Migration (MTD) ----
MIGRATE         = "MIGRATE"          # {type, new_port, token, epoch}  move notice (sealed)
MIGRATE_ACK     = "MIGRATE_ACK"      # {type, proof}                   HMAC over token+epoch


def encode(obj: dict) -> bytes:
    """dict -> bytes ready for framing.send_msg."""
    return json.dumps(obj).encode("utf-8")


def decode(data: bytes) -> dict:
    """bytes from framing.recv_msg -> dict."""
    return json.loads(data.decode("utf-8"))
