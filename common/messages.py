"""
    File: common/messages.py 
    
    Description: 
    - the shared message contract.
    - Every message on the wire is a JSON object with a "type" field. These constants
        are the single source of truth for those type names, so server and client never
        disagree about spelling. Agree on this file as a team FIRST; everyone imports it.

    - Helpers at the bottom turn a dict into bytes and back, so callers don't repeat 
        json.dumps / json.loads everywhere.
"""
import json

# ---- Client -> Server ----
LOGIN_HELLO   = "LOGIN_HELLO"    # {type, user, p2p_port}       start login (by name, for now)
LIST          = "LIST"           # {type}                       ask who's online
REQUEST       = "REQUEST"        # {type, peer}                 ask to chat with peer
ACCEPT        = "ACCEPT"         # {type, from}                 accept an invite
DECLINE       = "DECLINE"        # {type, from}                 decline an invite
LOGOUT        = "LOGOUT"         # {type}

# ---- Server -> Client ----
LOGIN_OK        = "LOGIN_OK"         # {type, user}
LOGIN_FAIL      = "LOGIN_FAIL"       # {type, reason}
USER_LIST       = "USER_LIST"        # {type, users:[...]}      available users
INVITE          = "INVITE"           # {type, from}             someone wants to chat
SESSION_START   = "SESSION_START"    # {type, session_id, peer, peer_host, peer_port, role}
BUSY            = "BUSY"             # {type, peer}             peer not available
ERROR           = "ERROR"            # {type, reason}

# ---- Client <-> Client (direct) ----
CHAT_MSG      = "CHAT_MSG"        # {type, session_id, text}
CHAT_END      = "CHAT_END"        # {type, session_id}


def encode(obj: dict) -> bytes:
    """dict -> bytes ready for framing.send_msg."""
    return json.dumps(obj).encode("utf-8")


def decode(data: bytes) -> dict:
    """bytes from framing.recv_msg -> dict."""
    return json.loads(data.decode("utf-8"))
