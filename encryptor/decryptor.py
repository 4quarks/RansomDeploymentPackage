#!/usr/bin/env python3
"""
---------------------------------------------------------------------------
Linux Decryptor "Kontuz" @4quarks
---------------------------------------------------------------------------
Summary:
Decryptor script for Kontuz encryptor in a Linux ransomware simulation using AES + RSA 

Key Features:
- Uses the client RSA private key to decrypt each AES key stored in encrypted files 
- Uses AES-CTR to decrypt content, matching the logic used during encryption

Warning:
- This code is for educational and authorized use only. Do not use on 
  systems you do not own or have explicit permission to operate on.
"""

import os
import argparse
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.backends import default_backend

# Constants
MARKER = b"KONTUZ"     # Tag to identify encrypted files
EXTENSION = ".kontuz"  # Extension of the encrypted files
CHUNK_SIZE = 100_000   # Size of AES-encrypted block

# Load the client private key (decrypted already)
def load_client_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

# AES-CTR decryption
def decrypt_chunk(data, key, nonce):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

# Decrypt a single file
def decrypt_file(file_path, client_privkey):
    data = file_path.read_bytes()
    if not data.startswith(MARKER):
        print(f"Skipping unmarked file: {file_path}")
        return

    try:
        len_m = len(MARKER)
        nonce = data[len_m : len_m + 16]
        enc_key = data[len_m + 16 : len_m + 16 + 256]
        enc_data = data[len_m + 16 + 256 :]

        aes_key = client_privkey.decrypt(
            enc_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        size = len(enc_data)
        if size < 1_048_576:
            decrypted = decrypt_chunk(enc_data, aes_key, nonce)
        elif size < 4_194_304:
            decrypted = decrypt_chunk(enc_data[:CHUNK_SIZE], aes_key, nonce) + enc_data[CHUNK_SIZE:]
        else:
            offset = size // 3
            decrypted = (
                enc_data[:offset] +
                decrypt_chunk(enc_data[offset:offset + CHUNK_SIZE], aes_key, nonce) +
                enc_data[offset + CHUNK_SIZE:]
            )

        restored_path = file_path.with_suffix('')
        restored_path.write_bytes(decrypted)
        file_path.unlink(missing_ok=True)
        print(f"Decrypted: {file_path}")
    except Exception as e:
        print(f"Failed to decrypt {file_path}: {e}")

# Walk through the directory and decrypt all files
def traverse_and_decrypt(path, client_privkey):
    for root, _, files in os.walk(path):
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix == EXTENSION:
                decrypt_file(fpath, client_privkey)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client-key", required=True, help="Decrypted client RSA private key (PEM)")
    parser.add_argument("--path", required=True, help="Folder containing encrypted files")
    args = parser.parse_args()

    if not Path(args.client_key).exists():
        print("Error: Client private key not found.")
        exit(1)

    if not Path(args.path).exists():
        print("Error: Target folder not found.")
        exit(1)

    print("Loading client private key...")
    client_key = load_client_key(args.client_key)

    print("Starting decryption...")
    traverse_and_decrypt(args.path, client_key)

    print("Decryption complete.")

if __name__ == "__main__":
    main()

