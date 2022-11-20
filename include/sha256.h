#pragma once

#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_BUFFER_SIZE 4096
#define SHA256_OUTPUT_SIZE 32

typedef struct {
    uint64_t size;
    uint32_t hash[8];
    uint8_t buffer[SHA256_BLOCK_SIZE];
    uint8_t digest[SHA256_OUTPUT_SIZE];
} _s_sha256_context;

char *sha256_fd(unsigned int fd, int print_contents, int encode);
char *sha256_str(char *str, size_t len, int encode);
