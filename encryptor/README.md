# Kontuz Ransomware Simulation Toolkit

This repository contains a simulated Linux-based ransomware deployment package for educational and training purposes only. It demonstrates hybrid encryption (AES + RSA) techniques similar to those seen in real-world ransomware like Monti and IceFire.

> ⚠️ **For educational and authorized use only.**
> Do not use this tool on systems you do not own or lack explicit permission to operate on.

## Key Features

| File                 | Description                                                 |
|----------------------|-------------------------------------------------------------|
| `encryptor.py`       | Encrypts files using AES-256-CTR + RSA.                     |
| `client_decryptor.py`| Decrypts the encrypted client private key using server RSA. |
| `decryptor.py`       | Recovers and decrypts all files using the client key.       |


1. Encryptor (`encryptor.py`):
   - Generates a new RSA key pair per victim (client).
   - Encrypts files using AES-256-CTR.
   - AES keys are encrypted using the client’s public RSA key.
   - The client's private RSA key is encrypted using a hardcoded server RSA public key.
   - Drops a ransom note in each directory where files are encrypted.

2. Client Key Decryptor (`client_decryptor.py`):
   - Requires the server’s RSA private key.
   - Decrypts the `client_privkey.encrypted` file and extracts the usable private key (`client_privkey.pem`).

3. File Decryptor (`decryptor.py`):
   - Uses the recovered client private key.
   - Decrypts the AES key stored in each file and restores original data.


## Usage

### 1. Encrypt Files

```bash
python3 encryptor.py --path /path/to/target
```

###  2. Decrypt Client Key
```bash
python3 client_decryptor.py --server-key server_private.pem
```
Produces client_privkey.pem

### 3. Decrypt Files
```bash
python3 decryptor.py --path /path/to/target --client-key client_privkey.pem
```

