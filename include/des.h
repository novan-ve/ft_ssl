#pragma once

#include "commands.h"
#include "ftio.h"

#include <stdint.h>

#define DES_BUFFER_SIZE 4096
#define DES_MAX_PASS_LEN 512
#define DES_SALT_MAGIC "Salted__"
#define DES_PBKDF1_ITERATIONS 1
#define DES_PBKDF2_ITERATIONS 10000
#define ENABLE_PBKDF2 0

typedef struct {
    int base;
    int decode;
    s_io io;
    char *iv_param;
    char *key_param;
    char *salt_param;
    char *password;
    uint8_t iv[8];
    uint8_t key[8];
    uint8_t salt[8];
} _s_des_config;

int handle_des(int argc, char *argv[], e_command command);

void des_block(uint8_t *dst, uint8_t *src, uint8_t *key,
               uint8_t *iv, int decode);
int des_generate_keyiv(char *pass, unsigned char *salt, size_t salt_len,
                       unsigned char *buf, size_t len, e_command command);
