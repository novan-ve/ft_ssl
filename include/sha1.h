#pragma once

#include <stdint.h>
#include <stddef.h>

#define SHA1_BLOCK_SIZE 64
#define SHA1_BUFFER_SIZE 4096
#define SHA1_OUTPUT_SIZE 20

typedef struct {
    uint64_t size;
    uint32_t hash[5];
    uint8_t buffer[SHA1_BLOCK_SIZE];
    uint8_t digest[SHA1_OUTPUT_SIZE];
} _s_sha1_context;

char *sha1_fd(unsigned int fd, int print_contents, int encode);
char *sha1_str(char *str, size_t len, int encode);
