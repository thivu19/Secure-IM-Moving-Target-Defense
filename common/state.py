"""
    File: common/state.py 

    Description: 
    - client chat states (project requirement 3.4).
    - The state machine:
        READY --REQUEST/INVITE--> PENDING --accepted--> CHATTING --end--> READY
    - Keeping states as an enum means code can check `if state is State.CHATTING`
        instead of comparing loose strings.
"""
from enum import Enum, auto


class State(Enum):
    READY = auto()      # logged in, free to chat
    PENDING = auto()    # an invite is outstanding (sent or received)
    CHATTING = auto()   # in an active session


# Allowed transitions, for reference and for the report's state diagram.
# (from_state, event) -> to_state
TRANSITIONS = {
    (State.READY,    "request_sent"):  State.PENDING,
    (State.READY,    "invite_recv"):   State.PENDING,
    (State.PENDING,  "accepted"):      State.CHATTING,
    (State.PENDING,  "declined"):      State.READY,
    (State.PENDING,  "cancelled"):     State.READY,
    (State.CHATTING, "ended"):         State.READY,
    (State.CHATTING, "peer_gone"):     State.READY,
}
