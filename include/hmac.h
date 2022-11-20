#pragma once

#include "digest.h"

unsigned char *hmac(char *key, size_t keylen,
                    unsigned char *msg, size_t msglen,
                    fn_digest_str digest,
                    size_t block_size, size_t output_size);
