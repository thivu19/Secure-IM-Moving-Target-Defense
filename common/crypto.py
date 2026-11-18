"""
    File: common/crypto.py
    Description:
    - Thin wrappers over the project's allowed primitives, in one place so the
      rest of the code never calls the crypto library directly.
    What's allowed (per the instructions):
    - RSA  -> SIGNING ONLY (never to encrypt or transport a key)
    - Diffie-Hellman -> our own, using Python's built-in pow()
    - keyed-hash (HMAC) built on SHA-256 -> for keystream, tags, and key derivation
    - a STANDARD pseudorandom generator (random) for nonces / DH private values
    NOTE (important for this project): we deliberately use the `random` module
    (a standard PRNG), NOT secrets / os.urandom. The assignment bans CSPRNGs.
   In a real system you would use a CSPRNG here; this is an assignment constraint.
    RSA key *generation* (in tools/genkeys.py) uses the cryptography library,
    which is fine: keys are long-term credentials provisioned before execution,
    and RSA is a permitted primitive.
"""
import hashlib
import hmac
import random
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
# --------------------------------------------------------------------------
# Diffie-Hellman parameters: RFC 3526, 2048-bit MODP group ("Group 14").
# A fixed, well-known safe prime and generator. Everyone uses the same group.
# --------------------------------------------------------------------------
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
DH_GENERATOR = 2
_DH_PRIV_BITS = 256          # size of each DH private exponent
# ---- randomness (STANDARD PRNG, per the assignment) ---
def gen_nonce(n_bytes: int = 16) -> bytes:
    """A fresh random nonce. Standard PRNG only (see module note)."""
    return bytes(random.getrandbits(8) for _ in range(n_bytes))
# ---- RSA: SIGNING ONLY ---
def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())
def sign(private_key, data: bytes) -> bytes:
    """RSA signature (PKCS1v15 + SHA-256) over data. NOT encryption."""
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
def verify(public_key, data: bytes, signature: bytes) -> bool:
    """True if the signature is valid for data under public_key."""
    from cryptography.exceptions import InvalidSignature
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
# ---- Diffie-Hellman (our own, via pow()) ---
def dh_keypair():
    """Returns (private_int, public_int). Private from the standard PRNG."""
    priv = random.getrandbits(_DH_PRIV_BITS)
    pub = pow(DH_GENERATOR, priv, DH_PRIME)
    return priv, pub
def dh_shared(their_public: int, my_private: int) -> bytes:
    """The shared secret g^(ab) mod p, as bytes (ready to feed a KDF)."""
    shared_int = pow(their_public, my_private, DH_PRIME)
    return shared_int.to_bytes(256, "big")      # 2048-bit value -> 256 bytes
# ---- HMAC-SHA256 helpers ---
def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """A keyed-hash tag over data. Used for integrity tags and as a PRF."""
    return hmac.new(key, data, hashlib.sha256).digest()
def hmac_verify(key: bytes, data: bytes, tag: bytes) -> bool:
    """Constant-time check of an HMAC tag."""
    return hmac.compare_digest(hmac_sha256(key, data), tag)
# ---- key derivation (HMAC used as a KDF) ---
def derive_key(shared_secret: bytes, label: str, length: int = 32) -> bytes:
    """Derive a purpose-specific key from the DH shared secret.
    label distinguishes keys, e.g. "enc:a->b", "mac:a->b", so each direction
    and each purpose (confidentiality vs integrity) gets its own key.
    """
    out = b""
    counter = 1
    while len(out) < length:
        block = hmac_sha256(shared_secret, label.encode() + bytes([counter]))
        out += block
        counter += 1
    return out[:length]
# ---- keystream for confidentiality (HMAC in counter mode) ---
def keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate `length` bytes of keystream to XOR with plaintext.
    Deterministic from (enc_key, nonce): the receiver reproduces the same
    keystream. A unique nonce per message means the keystream never repeats.
    """
    out = b""
    counter = 0
    while len(out) < length:
        block = hmac_sha256(enc_key, nonce + counter.to_bytes(4, "big"))
        out += block
        counter += 1
    return out[:length]
def xor(data: bytes, stream: bytes) -> bytes:
    """XOR plaintext/ciphertext with the keystream."""
    return bytes(a ^ b for a, b in zip(data, stream))