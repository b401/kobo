#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "kobo_lib_so.h"

#define LIB_PATH "/tmp/.kobo.so"

void write_so() {
    int fd = open(LIB_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    write(fd, kobo_lib_so, kobo_lib_so_len);
    close(fd);
}


int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Kobo DNS Rerouter\nUsage: %s <program> [args...]\n", argv[0]);
        return 1;
    }

    const char *dns_env = getenv("DNS");
    if (!dns_env) {
        fprintf(stderr, "[kobo] Please set the DNS environment variable.\n");
        return 1;
    }

    write_so();
    setenv("LD_PRELOAD", LIB_PATH, 1);

    printf("%s", argv[1]);
    execvp(argv[1], &argv[1]);
    perror("execvp");
    return 1;
}
