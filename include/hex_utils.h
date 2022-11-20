#pragma once

#include <stddef.h>

int is_hex(char c);
int hex_str_to_int(const char *input);
char *bytes_to_hex_str(const unsigned char *buf, int upper, size_t len);
