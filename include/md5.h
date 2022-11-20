#pragma once

#include <stdint.h>
#include <stddef.h>

#define MD5_BLOCK_SIZE 64
#define MD5_BUFFER_SIZE 4096
#define MD5_OUTPUT_SIZE 16

typedef struct {
    uint64_t size;
    uint32_t words[4];
    uint8_t buffer[MD5_BLOCK_SIZE];
    uint8_t digest[MD5_OUTPUT_SIZE];
} _s_md5_context;

char *md5_fd(unsigned int fd, int print_contents, int encode);
char *md5_str(char *str, size_t len, int encode);
