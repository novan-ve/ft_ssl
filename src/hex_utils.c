#include "hex_utils.h"

#include <stdlib.h>

int is_hex(char c)
{
    return ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
            (c >= 'a' && c <= 'f'));
}

char *bytes_to_hex_str(const unsigned char *buf, int upper, size_t len)
{
    size_t j = 0;
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char *str = malloc(len * 2 + 1);

    if (str) {
        for (size_t i = 0; i < len; i++) {
            str[j++] = digits[buf[i] >> 4];
            str[j++] = digits[buf[i] & 0xf];
        }
        str[j] = 0;
    }

    return (str);
}

int hex_str_to_int(const char *input)
{
    int nb = 0;
    int c;

    if (input) {
        for (int i = 0; i <= 1 && input[i]; i++) {
            c = input[i];
            if (!is_hex(c)) {
                return (-1);
            }
            c = (c >= 'a' && c <= 'f') ? c - 32 : c;
            c = (c >= 'A' && c <= 'F') ? c - 55 : c;
            c = (c >= '0' && c <= '9') ? c - 48 : c;
            c = (i == 0) ? c * 16 : c;
            nb += c;
        }
    }
    return (nb);
}
