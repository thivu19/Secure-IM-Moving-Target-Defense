# settings.py 

# shared constants (Section 3: functional IM only).
# Server 
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
MAX_CLIENTS = 50
IDLE_TIMEOUT_SEC = 300

# Client peer-to-peer listening ports (direct chat) 
P2P_PORT_MIN = 50000
P2P_PORT_MAX = 60000

# FOR LATER STAGES: Add DH/crypto/MTD constants here for Sections 4 and 5.
import os
# --- Section 4: Security --
KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
# (DH group constants live in common/crypto.py)
# --- Section 5: MTD (fill in during tuning) --
# MIGRATION_INTERVAL_SEC = 60
# RISK_THRESHOLD = 5
# RISK_COOLDOWN_SEC = 10