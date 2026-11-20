"""
    File: settings.py
    
    Description: Shared constants used across the server and clients.
"""
import os

# ---- Server ----
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
MAX_CLIENTS = 50
IDLE_TIMEOUT_SEC = 300

# ---- Client peer-to-peer ports (direct chat; reused by MTD migration) ----
P2P_PORT_MIN = 50000
P2P_PORT_MAX = 60000

# ---- Section 4: Security ----
# (DH group constants live in common/crypto.py)
KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")

# ---- Demo switch ----
# True prints what the security layer is doing. 
# Can change it to False to hide it.
DEBUG = True 

# ---- Section 5: MTD (uncomment and tune during implementation) ----
# MIGRATION_INTERVAL_SEC = 60     # move on a fixed schedule
# RISK_THRESHOLD         = 5      # risk score that triggers an early move
# RISK_COOLDOWN_SEC      = 10     # minimum gap between moves (anti forced-migration)
# MAX_MOVES              = 5      # cap on moves in a session
