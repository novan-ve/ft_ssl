#include "hmac.h"

#include <stdlib.h>
#include <errno.h>

char *compute_block_sized_key(char *key, size_t keylen,
                              fn_digest_str digest,
                              size_t block_size, size_t output_size)
{
    char *block_sized_key = malloc(block_size);

    if (!block_sized_key) {
        return (NULL);
    }
    if (keylen > block_size) {
        key = digest(key, keylen, 0);
        if (!key) {
            free(block_sized_key);
            return (NULL);
        }
        keylen = output_size;
        for (size_t i = 0; i < keylen; i++) {
            block_sized_key[i] = key[i];
        }
        free(key);
    }
    else {
        for (size_t i = 0; i < keylen; i++) {
            block_sized_key[i] = key[i];
        }
    }
    for (size_t i = keylen; i < block_size; i++) {
        block_sized_key[i] = 0;
    }
    return (block_sized_key);
}

unsigned char *hmac(char *key, size_t keylen,
                    unsigned char *msg, size_t msglen,
                    fn_digest_str digest,
                    size_t block_size, size_t output_size)
{
    char padded_msg[block_size + msglen];
    char outer_padded_hash[block_size + output_size];
    char *padded_msg_hash;
    char *block_sized_key;
    char *result;

    if (!key || !msg) {
        errno = EINVAL;
        return (NULL);
    }
    block_sized_key = compute_block_sized_key(key, keylen, digest,
                                              block_size, output_size);
    if (!block_sized_key) {
        return (NULL);
    }

    for (size_t i = 0; i < block_size; i++) {
        padded_msg[i] = block_sized_key[i] ^ 0x36;
    }
    for (size_t i = block_size; i < block_size + msglen; i++) {
        padded_msg[i] = msg[i - block_size];
    }

    padded_msg_hash = digest(padded_msg, block_size + msglen, 0);
    if (!padded_msg_hash) {
        free(block_sized_key);
        return (NULL);
    }

    for (size_t i = 0; i < block_size; i++) {
        outer_padded_hash[i] = block_sized_key[i] ^ 0x5c;
    }
    for (size_t i = block_size; i < block_size + output_size; i++) {
        outer_padded_hash[i] = padded_msg_hash[i - block_size];
    }
    result = digest(outer_padded_hash, block_size + output_size, 0);

    free(block_sized_key);
    free(padded_msg_hash);

    return((unsigned char*)result);
}