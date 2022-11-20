#pragma once

#include "commands.h"
#include "ftio.h"

#include <stdint.h>
#include <stddef.h>

#define BASE64_BUFFER_SIZE 9360

typedef struct {
    int decode;
    s_io io;
} _s_base64_config;

int handle_base64(int argc, char *argv[], e_command command);

int is_base64(char c);
int base64_io(int in_fd, int out_fd, int decode);
uint8_t *base64_encode(const uint8_t *input, size_t input_len,
                       size_t *output_len);
uint8_t *base64_decode(const uint8_t *buf, size_t buf_len,
                       size_t *output_len, int eof);
