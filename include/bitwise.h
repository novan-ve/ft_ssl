#pragma once

#include <stdint.h>

uint32_t uint8_to_uint32(uint8_t *buf);
uint32_t rotl(uint32_t x, uint32_t n);
uint32_t rotr(uint32_t x, uint32_t n);
uint32_t byteswap32(uint32_t x);
uint64_t byteswap64(uint64_t x);
int little_endian(void);
