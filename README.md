# Secure-IM-Moving-Target-Defense
Implemented a small Instant Messaging (IM) system in which users can find one another through a central server, establish private chat sessions, and communicate directly. The server never relays chat content. Client-to-client conversations are cryptographically protected.
--- 

## Requirements

- Python 3.11 or newer
- Dependencies listed in `requirements.txt`

--- 

## Tech stack & allowed primitives

The only third-party dependency is **`cryptography`** (used for RSA only). Everything
else is the Python standard library.

| Security need                   | What we use                                 | Library / function used                                                                        |
|---------------------------------|---------------------------------------------|------------------------------------------------------------------------------------------------|
| Authentication (signing)        | RSA signatures, PKCS#1 v1.5 over SHA-256    | `cryptography`: `private_key.sign` / `public_key.verify` (`padding.PKCS1v15`, `hashes.SHA256`) |
| Key provisioning                | RSA-2048 key-pair generation, PEM files     | `cryptography`: `rsa.generate_private_key`, `serialization` (PEM load/save)                    |
| Key exchange                    | Diffie-Hellman, RFC 3526 2048-bit group     | built-in `pow(g, x, p)` — modular exponentiation                                               |
| Confidentiality                 | HMAC-SHA256 keystream, XOR'd with plaintext | stdlib `hmac` + `hashlib` (`hmac.new(..., hashlib.sha256)`)                                    |
| Integrity                       | HMAC-SHA256 tag (verified before decrypt)   | stdlib `hmac` (`hmac.compare_digest` for the check)                                            |
| Freshness                       | sequence numbers + fresh nonces             | app logic + `random`                                                                           |
| Randomness                      | standard PRNG                               | stdlib `random` (`random.getrandbits`)                                                         |
| Transport                       | plain TCP sockets                           | stdlib `socket`                                                                                |
| Concurrency (multi-client)      | one thread per client                       | stdlib `threading`                                                                             |
| Message framing / serialization | length-prefixed frames, JSON, base64        | stdlib `struct`, `json`, `base64`                                                              |
| Paths / CLI args                | key paths, launcher arguments               | stdlib `os`, `sys`                                                                             |

So `cryptography` is used **only** for RSA (signing, verification, key generation, and PEM serialization) — not its symmetric ciphers (AES/Fernet), its Diffie-Hellman module, or its RNG.

**Deliberately not used** (per the project restrictions): no passwords; no RSA transport of the session key; no AES / DES / ChaCha20 / RSA encryption for confidentiality; no CSPRNGs (`secrets`, `os.urandom`); no TLS / SSL / SSH or other secure-transport library. The authentication, key exchange, message protection, and freshness logic are our own design.

---

## Setup

1. Create and activate a virtual environment:

```bash
python -m venv .venv

# On Mac:
source .venv/bin/activate     

# On Windows:
.venv\Scripts\activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Generate the RSA key pairs (one-time, before first run). Each user gets a long-term public/private key pair in `keys/` (gitignored, never committed):
```bash
python tools/genkeys.py alice bob
```

--- 

## Scope

**Note:**
- Section 3: Functional IM Application — done.
- Section 4: Security of the IM Application — done (this version).
- Section 5: Moving-Target Defense — to be added next.

---

## Running

Open separate terminals for the server and each client.

```bash
python main.py server          # Terminal 1
python main.py client alice    # Terminal 2
python main.py client bob      # Terminal 3
```

> Note: `settings.py` has a `DEBUG` flag (default `True`) that prints what the security layer is doing — signed login, key agreement, and the ciphertext that actually goes on the wire. Set it to `False` for clean output.

### Usage

Commands available once logged in:

| Command           | Action                             |
|-------------------|------------------------------------|
| `/list`           | Show available users               |
| `/chat <user>`    | Request a chat with a user         |
| `/accept <user>`  | Accept an incoming invitation      |
| `/decline <user>` | Decline an incoming invitation     |
| `/msg <text>`     | Send a message in the current chat |
| `/end`            | End the current chat               |
| `/quit`           | Log out and exit                   |
| `/help`           | List commands                      |

**Example:**

1. In **alice**: `/list`, then `/chat bob`
2. In **bob**: `/accept alice`
3. Either side: `/msg hello`
4. Either side: `/end`, then `/quit`

The server coordinates the chat setup, but messages are sent **directly** between the two clients — the server never relays chat content and never learns the session key.

### Demonstrating the security

**Attack tests** — run the attack demonstrations (no server needed, but run
`python tools/genkeys.py alice bob` first so the keys exist). They test the
security modules directly. Detailed/narrated output is the default:

```bash
python tools/test_attacks.py                 # all attacks, narrated
python tools/test_attacks.py --brief         # short PASS/FAIL summary

# Or can also run one attack at a time in the following ways:
python tools/test_attacks.py --case impersonate     # pretend to be another user
python tools/test_attacks.py --case login_replay    # replay a recorded login
python tools/test_attacks.py --case observe         # read a message off the wire
python tools/test_attacks.py --case modify          # tamper with a message
python tools/test_attacks.py --case fabricate       # forge a fake message
python tools/test_attacks.py --case replay          # resend an old message
python tools/test_attacks.py --case session         # replay into another session
```

They cover impersonation, login-replay, observe, modify, fabricate, replay, and cross-session replay — each shown on both the client-server and client-to-client channels.

**Live impersonation example scenario** — on the running system, try to log in as one user while signing with another user's key. The server rejects the forged signature:

```bash
python main.py client alice --key bob        # claims to be alice, signs with bob's key -> REJECTED
```

A normal login (`python main.py client alice`, no `--key`) is unaffected.

### Suggested demo flow

**Live (run on `main.py`):**
- *Normal operation* — log in, `/list`, `/chat`, `/accept`, `/msg`, `/end`
  (a normal chat; shows discovery, session setup, and termination).
- *Key establishment* — during `/chat` → `/accept`, point to the line
  `[secure] authenticated key exchange ... (server never saw it)`.
- *Observe* — while chatting, show the `[wire] ct=...` line (or a packet capture
  of the chat port): the message is ciphertext on the wire, readable only to the peer.
- *Impersonation* — `python main.py client alice --key bob` is rejected, next to a
  normal `python main.py client alice` that works.

**Via the script (`python tools/test_attacks.py`):**
- *modify, fabricate, replay, login-replay (and cross-session replay)* - script performs them and shows each being rejected.

Together these cover the Section 4 demo items (normal operation, authentication and
attempts to violate it, key establishment, message protection, and termination).

---

## Security

- **Authentication** — users log in with a signed challenge-response (RSA
  signatures over a fresh-nonce transcript); no passwords. A recorded login
  cannot be replayed.
- **Session establishment** — the two clients run an authenticated Diffie-Hellman
  handshake directly, so each proves it is the intended peer for that session and
  the server never sees the shared key.
- **Confidentiality** — messages are protected with an HMAC-SHA256 keystream
  (no banned ciphers such as AES/RSA encryption).
- **Integrity** — every message carries an HMAC tag, verified before decryption.
- **Freshness** — per-direction sequence numbers reject replayed or stale messages;
  the session id binds each message to its conversation.

Keys are provisioned up front with `tools/genkeys.py` and stored as PEM files in
`keys/`, which is gitignored.

---

## Requirement → code map

Mapping of requirement to code: To show where each requirement was implemented.

**Section 3 — Functional IM**

| Requirement | Implemented in |
|---|---|
| 3.1 Server & client operation (multiple clients, connect/disconnect) | `server/server.py` (threaded accept loop), `server/coordinator.py` |
| 3.2 User discovery & chat establishment | `server/coordinator.py` (`available_users`, `start_invite`, `confirm_session`); `server/server.py` (LIST / REQUEST / ACCEPT handlers) |
| 3.3 Direct client-to-client communication | `client/chat.py` (`ChatConnection`); `client/client.py` (`_start_chat`) |
| 3.4 Session management | `server/coordinator.py` + `common/state.py` (state machine); `client/client.py` (`/end`, `/quit`) |

**Section 4 — Security**

| Requirement | Implemented in |
|---|---|
| 4.2 Authentication & authorization | `client/auth.py`, `server/auth.py` (signed challenge-response); `server/coordinator.py` (authorization) |
| 4.3 Secure session establishment | `client/handshake.py` (authenticated Diffie-Hellman) |
| 4.4 Confidentiality | `common/secure_channel.py` (`seal`/`open`) + `common/crypto.py` (`keystream`) |
| 4.5 Integrity | `common/secure_channel.py` (HMAC tag, verified before decrypt) |
| 4.6 Freshness & protocol state | `common/secure_channel.py` (sequence numbers + session id); `server/coordinator.py` (state machine) |


**Section 5 — Moving-Target Defense**
To be added in next stage

---

## Project Structure

Current layout (Sections 3 + 4):

```
Secure-IM-Moving-Target-Defense/
├── main.py                  # Launcher: python main.py server | client <user>
├── settings.py              # Shared constants (host, ports, KEYS_DIR, DEBUG)
├── requirements.txt
├── keys/                    # RSA key pairs (generated by genkeys.py; gitignored)
├── common/                  # Shared by server and client
│   ├── __init__.py
│   ├── framing.py           # Length-prefixed message framing over TCP
│   ├── messages.py          # Message types + encode/decode helpers
│   ├── state.py             # Client states (READY / PENDING / CHATTING)
│   ├── crypto.py            # RSA signing, Diffie-Hellman, HMAC, KDF, keystream
│   └── secure_channel.py    # seal()/open(): confidentiality + integrity + freshness
├── server/
│   ├── __init__.py
│   ├── coordinator.py       # User table, availability, chat setup
│   ├── auth.py              # Server-side signed-login verification + authorization
│   └── server.py            # Accept loop + per-client dispatch (sealed control loop)
├── client/
│   ├── __init__.py
│   ├── client.py            # Command-line client (prompt + sealed server connection)
│   ├── chat.py              # Direct client-to-client chat (handshake + sealed messages)
│   ├── auth.py              # Client-side signed login
│   └── handshake.py         # Authenticated client-to-client key exchange
└── tools/
    ├── __init__.py
    ├── genkeys.py           # One-time RSA key provisioning
    └── test_attacks.py      # Attack demonstrations (observe/modify/fabricate/replay/...)
```
