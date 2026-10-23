"""
    File: common/framing.py
    
    Description: 
    - Length-prefixed message framing over a TCP socket. 
    - TCP is a byte stream: one send() can arrive as several recv() chunks, or two
        sends can arrive glued together. We fix that by prefixing every message with
        its length as a 4-byte big-endian integer.
    - This file is the foundation everything else sends through, including the
    encrypted frames added later.
"""
import struct

MAX_MSG = 64 * 1024  # refuse absurdly large frames (basic DoS hygiene)


def send_msg(sock, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:  # peer closed the connection
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_msg(sock) -> bytes:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    if length > MAX_MSG:
        raise ValueError(f"frame too large: {length}")
    return _recv_exact(sock, length)
