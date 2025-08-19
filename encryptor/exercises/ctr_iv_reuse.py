#!/usr/bin/env python3
import os, shutil, subprocess, secrets

# Define two plaintexts files
PLAINTEXT_1 = b"This is the file we will have in plain text."
FILENAME_P1 = "p1.txt"
FILENAME_C1 = "c1.enc"

PLAINTEXT_2 = b"This is the file we want to decrypt."
FILENAME_P2 = "p2.txt"
FILENAME_C2 = "c2.enc"

FILENAME_XOR = "c_xor.bin"

def encrypt_ctr(filename_plaintext, filename_cipher, key_hex, iv_hex):
    openssl_cmd = ["openssl", "enc", "-aes-256-ctr", "-K", key_hex, "-iv", iv_hex,
                 "-in", filename_plaintext, "-out", filename_cipher]
    subprocess.run(openssl_cmd, check=True, capture_output=False)

def prepare_demo():
    # Check if OpenSSL CLI is available
    if not shutil.which("openssl"):
        raise SystemExit("OpenSSL not found. Please install it and ensure 'openssl' is in your PATH.")

    # Save plaintexts into files
    with open(FILENAME_P1, "wb") as file:
        file.write(PLAINTEXT_1)
    with open(FILENAME_P2, "wb") as file:
        file.write(PLAINTEXT_2)

    # Generate one random key and IV
    key_hex = secrets.token_hex(32)   # 32 bytes = 256 bits (AES-256)
    iv_hex  = secrets.token_hex(16)   # 16 bytes = 128 bits (block size)

    print(f"KEY = {key_hex}")
    print(f"IV  = {iv_hex}")

    # Encrypt both plaintexts with AES-256-CTR, using same key+IV
    encrypt_ctr(FILENAME_P1, FILENAME_C1, key_hex, iv_hex)
    encrypt_ctr(FILENAME_P2, FILENAME_C2, key_hex, iv_hex)


def xor_bytes(bytes_a: bytes, bytes_b: bytes) -> bytes:
    # XOR two byte strings
    return bytes(x ^ y for x, y in zip(bytes_a, bytes_b))

def break_ctr() -> bytes:
    # Read the ciphertexts and plaintexts back into memory
    ciphertext_one = open(FILENAME_C1, "rb").read()
    ciphertext_two = open(FILENAME_C2, "rb").read()

    # Read the known plain text file
    plaintext_1  = open(FILENAME_P1, "rb").read()

    # XOR of ciphertexts: C1 ⊕ C2 = (P1 ⊕ KS) ⊕ (P2 ⊕ KS) = P1 ⊕ P2
    ciphertexts_xored = xor_bytes(ciphertext_one, ciphertext_two)
    with open(FILENAME_XOR, "wb") as file:
        file.write(ciphertexts_xored)

    # Recover P2 by XORing (P1 ⊕ P2) with known P1 -> P2 = (P1 ⊕ P2) ⊕ P1
    recovered_plaintext_2 = xor_bytes(ciphertexts_xored, plaintext_1)

    return recovered_plaintext_2

def main():
    prepare_demo()
    recovered_plaintext_2 = break_ctr()
    plaintext_2  = open(FILENAME_P2, "rb").read()

    # Print results
    print("Original P2:")
    print(plaintext_2.decode(errors="replace"))
    print("Recovered P2 breaking CTR:")
    print(recovered_plaintext_2.decode(errors="replace"))

    # Check if recovery worked
    if recovered_plaintext_2 == plaintext_2[:len(recovered_plaintext_2)]:
        print("Success: P2 was recovered using only C1, C2, and known P1.")
    else:
        print("Something went wrong — recovered text doesn’t match.")

if __name__ == "__main__":
    main()

