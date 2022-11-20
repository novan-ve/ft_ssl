#pragma once

#include <stddef.h>
#include <stdint.h>

#define RAND_BUFFER_SIZE 256

int rand_fill(void *d, size_t n);
uint32_t srandom_nb(const char *seed_file);
uint32_t srandom_prime(const char *seed_file, int precision, int print);
