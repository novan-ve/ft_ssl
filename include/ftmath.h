#pragma once

#include <stdint.h>
#include <stddef.h>

size_t intlen(size_t x);
size_t bitlen(size_t x);
uint64_t modular_inverse(uint64_t x, uint64_t y);
uint64_t power_mod(uint64_t x, uint64_t y, uint64_t p);
int miller_rabin(uint64_t n, uint64_t d);
int is_prime(uint64_t n, int k, int print);
