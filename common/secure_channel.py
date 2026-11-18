"""
    File: common/secure_channel.py
    Description:
    - The heart of Section 4. Wraps one established session (shared secret +
      session id) and protects every message with confidentiality (4.4),
      integrity (4.5), and freshness (4.6).
    - seal(plaintext) -> dict ready to send; open(dict) -> plaintext back, or
      raises SecurityError (the caller drops the message, doesn't act on it).
    Matches the design report (Section VII):
    - keystream keyed by the confidentiality key + sequence number + direction
      + block counter. Direction is captured by the per-direction keys; the
      sequence number makes each message's keystream unique (no random nonce).
    - HMAC over the session id + sender identity + sequence number (+ ciphertext).
    - separate keys per direction and per purpose (enc vs mac), from the KDF.
    - encrypt-then-MAC: verify the tag BEFORE decrypting.
    - bytes can't go in JSON, so ct/tag are base64 strings on the wire.
"""
import base64
from common import crypto
class SecurityError(Exception):
    """Raised when a message fails a security check (drop it, don't act on it)."""
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()
def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode())
class SecureChannel:
    def __init__(self, shared_secret: bytes, session_id: str,
                 is_initiator: bool, me: str):
        # Four keys from the one shared secret. Both sides derive all four; each
        # side picks the opposite send/recv pair (is_initiator from the server role).
        i2r_enc = crypto.derive_key(shared_secret, "enc:init->resp")
        i2r_mac = crypto.derive_key(shared_secret, "mac:init->resp")
        r2i_enc = crypto.derive_key(shared_secret, "enc:resp->init")
        r2i_mac = crypto.derive_key(shared_secret, "mac:resp->init")
        if is_initiator:
            self._send_enc, self._send_mac = i2r_enc, i2r_mac
            self._recv_enc, self._recv_mac = r2i_enc, r2i_mac
        else:
            self._send_enc, self._send_mac = r2i_enc, r2i_mac
            self._recv_enc, self._recv_mac = i2r_enc, i2r_mac
        self.me = me                    # sender identity, bound into the MAC
        self.session_id = session_id
        self._send_seq = 0              # last sequence number we sent
        self._recv_seq = 0              # highest sequence number we accepted
 # ---- sending ---
    def seal(self, plaintext: bytes) -> dict:
        self._send_seq += 1
        seq = self._send_seq
        seq_bytes = seq.to_bytes(8, "big")
        # keystream is unique per message (per-direction key + sequence number)
        ks = crypto.keystream(self._send_enc, seq_bytes, len(plaintext))
        ct = crypto.xor(plaintext, ks)
        # encrypt-then-MAC: tag over session id, sender, seq, and ciphertext
        header = f"{self.session_id}|{self.me}|{seq}".encode()
        tag = crypto.hmac_sha256(self._send_mac, header + ct)
        return {"session_id": self.session_id, "sender": self.me, "seq": seq,
                "ct": _b64(ct), "tag": _b64(tag)}
    # ---- receiving ---
    def open(self, msg: dict) -> bytes:
        try:
            sid = msg["session_id"]
            sender = msg["sender"]
            seq = int(msg["seq"])
            ct = _unb64(msg["ct"])
            tag = _unb64(msg["tag"])
        except (KeyError, ValueError, TypeError):
            raise SecurityError("malformed secure message")
        # 1. session binding
        if sid != self.session_id:
            raise SecurityError("wrong session id")
        # 2. integrity — verify the tag BEFORE decrypting
        header = f"{sid}|{sender}|{seq}".encode()
        if not crypto.hmac_verify(self._recv_mac, header + ct, tag):
            raise SecurityError("integrity check failed")
        # 3. freshness — sequence number must strictly increase
        if seq <= self._recv_seq:
            raise SecurityError("stale or replayed message")
        self._recv_seq = seq
        # 4. decrypt
        ks = crypto.keystream(self._recv_enc, seq.to_bytes(8, "big"), len(ct))
        return crypto.xor(ct, ks)
