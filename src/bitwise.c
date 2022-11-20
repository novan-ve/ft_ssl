#include "bitwise.h"

uint32_t uint8_to_uint32(uint8_t *buf)
{
    return ((uint32_t)(buf[3]) << 24 |
            (uint32_t)(buf[2]) << 16 |
            (uint32_t)(buf[1]) << 8 |
            (uint32_t)(buf[0]));
}

uint32_t rotl(uint32_t x, uint32_t n)
{
    return ((x << n) | (x >> (32 - n)));
}

uint32_t rotr(uint32_t x, uint32_t n)
{
    return ((x >> n) | (x << (32 - n)));
}

uint32_t byteswap32(uint32_t x) {
    return (((x >> 24) & 0x000000FFU) |
            ((x >>  8) & 0x0000FF00U) |
            ((x <<  8) & 0x00FF0000U) |
            ((x << 24) & 0xFF000000U));
}

uint64_t byteswap64(uint64_t x)
{
    return (((x >> 56) & 0x00000000000000FFULL) |
            ((x >> 40) & 0x000000000000FF00ULL) |
            ((x >> 24) & 0x0000000000FF0000ULL) |
            ((x >>  8) & 0x00000000FF000000ULL) |
            ((x <<  8) & 0x000000FF00000000ULL) |
            ((x << 24) & 0x0000FF0000000000ULL) |
            ((x << 40) & 0x00FF000000000000ULL) |
            ((x << 56) & 0xFF00000000000000ULL));
}

int little_endian(void)
{
    int n = 1;

    return (*(char*)&n == 1);
}
