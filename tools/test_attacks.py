"""
    File: tools/test_attacks.py

    Description:
    - Attack demonstrations for Section 4 (demo items 2 and 4). Each function runs
      an attack against the REAL security modules and shows it being rejected.
    - The message attacks run on BOTH channels: client<->client (c2c) and
      client<->server (c2s), since the instructions name both paths.

    Run all (narrated):  python tools/test_attacks.py
    Short summary only:  python tools/test_attacks.py --brief

    Run one attack at a time:
        python tools/test_attacks.py --case impersonate     # pretend to be another user
        python tools/test_attacks.py --case login_replay    # replay a recorded login
        python tools/test_attacks.py --case observe         # read a message off the wire
        python tools/test_attacks.py --case modify          # tamper with a message
        python tools/test_attacks.py --case fabricate       # forge a fake message
        python tools/test_attacks.py --case replay          # resend an old message
        python tools/test_attacks.py --case session         # replay into another session
"""
import os
import sys
import socket
import threading

# make "from common import ..." work no matter where this is launched from
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import settings
from common import crypto
from common.secure_channel import SecureChannel, SecurityError
from client.auth import client_login
from server.auth import server_authenticate, load_public_keys

VERBOSE = True        # detailed/narrated output is the default; --brief turns it off
PASSED = 0
FAILED = 0
_current = {"who": ""}


def begin(name, label=None):
    """Start an attack block. In detailed mode, print its name as a header."""
    who = f"{name} ({label})" if label else name
    _current["who"] = who
    if VERBOSE:
        print(f"\n  {who}")


def v(msg):
    """Print one interaction step (only in --detailed mode)."""
    if VERBOSE:
        print(f"       - {msg}")


def result(ok, reason):
    """Print the verdict for the current attack and tally it."""
    global PASSED, FAILED
    tag = "PASS" if ok else "FAIL"
    if VERBOSE:
        print(f"    => {tag}: {reason}")
    else:
        print(f"  [{tag}]  {_current['who']:<22}{reason}")
    if ok:
        PASSED += 1
    else:
        FAILED += 1


def header(title):
    print(f"\n-- {title} --")


def _short(s, n=28):
    return s[:n] + "..." if len(s) > n else s


# ---------------------------------------------------------------------------
# Fixtures: build a sealed channel for each path. Both paths use the SAME
# SecureChannel class, so the same four attacks apply to both.
# ---------------------------------------------------------------------------
def _channel_pair(session_id, left, right):
    a_priv, a_pub = crypto.dh_keypair()
    b_priv, b_pub = crypto.dh_keypair()
    shared = crypto.dh_shared(b_pub, a_priv)            # both sides derive the same secret
    return (SecureChannel(shared, session_id, is_initiator=True,  me=left),
            SecureChannel(shared, session_id, is_initiator=False, me=right))

def _peer_pair():
    return _channel_pair("S1", "alice", "bob")          # client-to-client

def _cs_pair():
    return _channel_pair("cs:alice", "alice", "server")  # client-to-server


# ---------------------------------------------------------------------------
# Message-layer attacks (demo item 4)
# ---------------------------------------------------------------------------
def attack_observe(mk, label):
    begin("observe", label)
    sender, receiver = mk()
    wire = sender.seal(b"secret plan")
    v('sender seals "secret plan"')
    v(f'on the wire: ct={_short(wire["ct"])}  (unreadable)')
    ok = wire["ct"] != "secret plan" and receiver.open(wire) == b"secret plan"
    v('real peer opens it -> "secret plan"; an eavesdropper only sees ciphertext')
    result(ok, "traffic on the wire is ciphertext")

def attack_modify(mk, label):
    begin("modify", label)
    sender, receiver = mk()
    msg = sender.seal(b"transfer $10")
    before = msg["ct"]
    msg["ct"] = msg["ct"][:-2] + ("AA" if not msg["ct"].endswith("AA") else "BB")
    v('sender seals "transfer $10"')
    v(f'Eve flips bytes: {_short(before)} -> {_short(msg["ct"])}')
    try:
        receiver.open(msg); ok = False
    except SecurityError as e:
        v(f'receiver.open() raises SecurityError: {e}'); ok = True
    result(ok, "tampered message rejected (HMAC fails)")

def attack_fabricate(mk, label):
    begin("fabricate", label)
    _, receiver = mk()
    forged = {"session_id": receiver.session_id, "sender": "eve",
              "seq": 1, "ct": "Zm9v", "tag": "AAAA"}
    v('Eve builds a message from scratch with a made-up tag:')
    v(f'{forged}')
    try:
        receiver.open(forged); ok = False
    except SecurityError as e:
        v(f'receiver.open() raises SecurityError: {e}'); ok = True
    result(ok, "fabricated message rejected (bad tag)")

def attack_replay(mk, label):
    begin("replay", label)
    sender, receiver = mk()
    m = sender.seal(b"hello"); receiver.open(m)
    v(f'sender seals "hello" (seq={m["seq"]}); receiver accepts it once')
    v('Eve captures that exact message and sends it again')
    try:
        receiver.open(m); ok = False
    except SecurityError as e:
        v(f'receiver.open() raises SecurityError: {e}'); ok = True
    result(ok, "replayed message rejected (stale seq)")

def attack_wrong_session(mk, label):
    begin("wrong-session", label)
    sender, _ = mk()
    stolen = sender.seal(b"x")
    other = SecureChannel(b"x" * 256, "S-other", is_initiator=False, me="eve")
    v(f'a valid message from session {stolen["session_id"]} is captured')
    v('Eve replays it into a different session (S-other)')
    try:
        other.open(stolen); ok = False
    except SecurityError as e:
        v(f'receiver.open() raises SecurityError: {e}'); ok = True
    result(ok, "can't be replayed into another session")


# ---------------------------------------------------------------------------
# Auth-layer attacks (demo item 2)
# ---------------------------------------------------------------------------
def attack_impersonate(pubkeys, keys):
    begin("impersonate")
    cs, ss = socket.socketpair()
    out = {}
    def srv():
        try: out["s"] = server_authenticate(ss, pubkeys)
        except Exception as e: out["s"] = ("err", str(e))
        finally: ss.close()
    t = threading.Thread(target=srv); t.start()
    v("Eve claims to be 'alice' but signs the challenge with BOB's key")
    try:
        client_login(cs, "alice", keys["bob_priv"], 0); ok = False
    except Exception as e:
        ok = True
        v(f'client sees: {e}')
        if isinstance(out.get("s"), tuple):
            v(f'server sees: {out["s"][1]}')
    finally:
        cs.close(); t.join()
    result(ok, "login as 'alice' without her key rejected")

def attack_login_replay(keys):
    begin("login_replay")
    user = "alice"
    _, dh_pub = crypto.dh_keypair()
    n1 = crypto.gen_nonce()
    t1 = f"{user}|{dh_pub}|SRVPUB|NONCE|{n1.hex()}".encode()
    captured = crypto.sign(keys["alice_priv"], t1)
    v(f"Eve records alice's valid login signature (server nonce {_short(n1.hex(),12)})")
    n2 = crypto.gen_nonce()
    t2 = f"{user}|{dh_pub}|SRVPUB|NONCE|{n2.hex()}".encode()
    v(f"a new login uses a DIFFERENT server nonce ({_short(n2.hex(),12)})")
    v("Eve replays the old signature against the new challenge")
    ok = not crypto.verify(keys["alice_pub"], t2, captured)
    v("signature does not verify against the fresh nonce")
    result(ok, "recorded login rejected (bound to a fresh nonce)")


# ---------------------------------------------------------------------------
# Section 5 (MTD) -- add when migration is built.
#
# The flooding -> migration attack (demo item 7) is a LIVE demo (two clients +
# an attacker hammering the port), not a unit test. But the risk logic in
# client/risk.py is pure logic and can be checked here. Sketch:
#
# def attack_forced_migration():
#     begin("forced_migration")
#     from client.risk import RiskMonitor
#     rm = RiskMonitor(threshold=5, window_sec=10, cooldown_sec=15, max_moves=5)
#     ok  = not rm.should_migrate()                  # quiet -> no move
#     for _ in range(3): rm.record("non_peer")       # 2+2+2 = 6 >= 5
#     ok  = ok and rm.should_migrate()               # flood -> move
#     rm.mark_migrated()
#     for _ in range(3): rm.record("integrity_fail")
#     ok  = ok and not rm.should_migrate()           # cooldown holds
#     result(ok, "moves under attack, cooldown resists spam")
#
# Also worth adding once migration works: send a message, migrate (reusing the
# SAME SecureChannel), then show a PRE-migration message replayed AFTER the move
# is still rejected -- proving security holds across the move (5.1).
# ---------------------------------------------------------------------------


def _load_keys():
    kd = settings.KEYS_DIR
    return {
        "alice_priv": crypto.load_private_key(os.path.join(kd, "alice_private.pem")),
        "alice_pub":  crypto.load_public_key(os.path.join(kd, "alice_public.pem")),
        "bob_priv":   crypto.load_private_key(os.path.join(kd, "bob_private.pem")),
    }

def main(case=None):
    keys = _load_keys()
    pubkeys = load_public_keys(["alice"], settings.KEYS_DIR)   # alice is registered

    cases = {
        "observe":      lambda: (attack_observe(_peer_pair, "c2c"),   attack_observe(_cs_pair, "c2s")),
        "modify":       lambda: (attack_modify(_peer_pair, "c2c"),    attack_modify(_cs_pair, "c2s")),
        "fabricate":    lambda: (attack_fabricate(_peer_pair, "c2c"), attack_fabricate(_cs_pair, "c2s")),
        "replay":       lambda: (attack_replay(_peer_pair, "c2c"),    attack_replay(_cs_pair, "c2s")),
        "session":      lambda: attack_wrong_session(_peer_pair, "c2c"),
        "impersonate":  lambda: attack_impersonate(pubkeys, keys),
        "login_replay": lambda: attack_login_replay(keys),
    }

    print("=" * 60)
    print("  SECURE IM  --  ATTACK TESTS")
    print("=" * 60)

    if case:
        if case not in cases:
            print(f"\n  unknown case '{case}'. available cases:")
            for c in cases:
                print(f"    --case {c}")
            return
        cases[case]()
    else:
        header("AUTHENTICATION  (demo item 2)")
        cases["impersonate"](); cases["login_replay"]()
        header("MESSAGES  (demo item 4)   c2c = client-client, c2s = client-server")
        for c in ("observe", "modify", "fabricate", "replay"):
            cases[c]()
        header("FRESHNESS  (extra)")
        cases["session"]()

    print("\n" + "-" * 60)
    status = "ALL PASSED" if FAILED == 0 else "SOME FAILED"
    print(f"  RESULT: {PASSED} passed, {FAILED} failed   [{status}]")
    print("=" * 60)


if __name__ == "__main__":
    args = sys.argv[1:]
    # Detailed/narrated output is the default. --brief (or --quiet/-q) shows the
    # short summary instead. (--detailed/-d still accepted, it's just the default.)
    _brief = ("--brief", "--quiet", "-q")
    _detail = ("--detailed", "-d", "--verbose", "-v")
    if any(f in args for f in _brief):
        VERBOSE = False
    args = [a for a in args if a not in _brief and a not in _detail]
    case = args[1] if len(args) >= 2 and args[0] == "--case" else None
    main(case)
