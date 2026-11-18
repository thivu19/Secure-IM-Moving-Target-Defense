"""
    File: tools/genkeys.py
    Description:
    - One-time key provisioning. Generates an RSA public/private key pair for
      each user and saves them as PEM files in keys/.
    - The server loads everyone's PUBLIC keys; each client loads its OWN private
      key. Private keys must never be committed to the repo (keys/ is gitignored).
    RSA here is a long-term credential provisioned before execution, so using the
    cryptography library to generate it is fine (RSA is a permitted primitive).
    Run:  python tools/genkeys.py alice bob carol
          python tools/genkeys.py                 # defaults to alice, bob
"""
import os
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "keys")
def generate_for(user: str):
    # 2048-bit RSA, public exponent 65537 (standard choices)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_path = os.path.join(KEYS_DIR, f"{user}_private.pem")
    pub_path = os.path.join(KEYS_DIR, f"{user}_public.pem")
    # private key -> PEM (unencrypted, for simplicity; hosts are assumed uncompromised)
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    # public key -> PEM (this is what the server stores / others use to verify)
    with open(pub_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print(f"  {user}: {os.path.basename(priv_path)} + {os.path.basename(pub_path)}")
def main():
    users = sys.argv[1:] or ["alice", "bob"]
    os.makedirs(KEYS_DIR, exist_ok=True)
    print(f"Generating RSA key pairs in {KEYS_DIR}/")
    for user in users:
        generate_for(user)
    print("Done. Keep the *_private.pem files out of the repo (keys/ is gitignored).")
if __name__ == "__main__":
    main()
    