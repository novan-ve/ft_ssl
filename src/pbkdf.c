#include "pbkdf.h"
#include "hmac.h"
#include "libft.h"
#include "bitwise.h"
#include "md5.h"

#include <errno.h>

int pbkdf1(char *pass, size_t passlen,
           unsigned char *salt, size_t saltlen, size_t iter,
           fn_digest_str digest, size_t output_size,
           size_t keylen, unsigned char *key)
{
    size_t pos = 0;
    size_t blocks = 0;
    size_t len = output_size + passlen + saltlen;
    char block[len];
    char *output;

    if (!pass || !salt || !key || !iter) {
        errno = EINVAL;
        return (-1);
    }
    blocks = keylen / output_size;
    if (keylen % output_size) {
        blocks++;
    }

    ft_memcpy(block, pass, passlen);
    ft_memcpy(block + passlen, salt, saltlen);
    output = digest(block, passlen + saltlen, 0);
    if (!output) {
        return (-1);
    }
    for (size_t i = 0, j = 0; i < blocks; i++, j = 0) {
        if (i == 0) {
            j++;
        }
        for (; j < iter; j++) {
            ft_memcpy(block, output, output_size);
            ft_memcpy(block + output_size, pass, passlen);
            ft_memcpy(block + output_size + passlen, salt, saltlen);
            free(output);
            output = digest(block, len, 0);
            if (!output) {
                return (-1);
            }
        }
        if (pos + output_size > keylen) {
            ft_memcpy(key + pos, output, (keylen - pos));
        }
        else {
            ft_memcpy(key + pos, output, output_size);
        }
        pos += output_size;
    }
    free(output);
    return (0);
}

int pbkdf2(char *pass, size_t passlen,
           unsigned char *salt, size_t saltlen, size_t iter,
           fn_digest_str digest, size_t block_size,
           size_t output_size, size_t keylen, unsigned char *key)
{
    unsigned char padded_salt[saltlen + 4];
    unsigned char block[output_size];
    unsigned char *output;
    unsigned char *tmp;
    size_t blocks;
    size_t pos = 0;

    blocks = keylen / output_size;
    if (keylen % output_size) {
        blocks++;
    }

    ft_memcpy(padded_salt, salt, saltlen);

    for (uint32_t i = 1; i <= blocks; i++) {
        *((uint32_t*)(padded_salt + saltlen)) = little_endian() ? byteswap32(i) : i;

        tmp = hmac(pass, passlen, padded_salt, saltlen + 4,
                   digest, block_size, output_size);
        if (!tmp) {
            return (-1);
        }
        ft_memcpy(block, tmp, output_size);

        for (size_t j = 2; j <= iter; j++) {
            output = hmac(pass, passlen, tmp, output_size,
                          digest, block_size, output_size);
            free(tmp);
            if (!output) {
                return (-1);
            }
            for (size_t k = 0; k < output_size; k++) {
                block[k] ^= output[k];
            }
            tmp = output;
        }
        free(output);

        if (pos + output_size > keylen) {
            ft_memcpy(key + pos, block, (keylen - pos));
        }
        else {
            ft_memcpy(key + pos, block, output_size);
        }
        pos += output_size;
    }
    return (0);
}
