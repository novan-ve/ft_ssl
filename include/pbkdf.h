#pragma once

#include "digest.h"

int pbkdf1(char *pass, size_t passlen,
           unsigned char *salt, size_t saltlen, size_t iter,
           fn_digest_str digest, size_t output_size,
           size_t keylen, unsigned char *key);

int pbkdf2(char *pass, size_t passlen,
           unsigned char *salt, size_t saltlen, size_t iter,
           fn_digest_str digest, size_t block_size,
           size_t output_size, size_t keylen, unsigned char *key);
