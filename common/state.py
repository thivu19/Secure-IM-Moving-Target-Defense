"""
    File: common/state.py
    
    Description:
    - Client chat states 
        READY --request/invite--> PENDING --accepted--> CHATTING --end--> READY
    - TRANSITIONS below is reference documentation (mirrors the design report's
      state diagram). The code sets states directly; nothing imports this table,
      it's here so the allowed moves are written down in one place.
"""
from enum import Enum, auto


class State(Enum):
    READY = auto()      # logged in, free to chat
    PENDING = auto()    # an invite is outstanding (sent or received)
    CHATTING = auto()   # in an active session


# Allowed transitions, for reference and for the report's state diagram.
#   (from_state, event) -> to_state
TRANSITIONS = {
    (State.READY,    "request_sent"): State.PENDING,
    (State.READY,    "invite_recv"):  State.PENDING,
    (State.PENDING,  "accepted"):     State.CHATTING,
    (State.PENDING,  "declined"):     State.READY,
    (State.PENDING,  "cancelled"):    State.READY,
    (State.CHATTING, "ended"):        State.READY,
    (State.CHATTING, "peer_gone"):    State.READY,
}
