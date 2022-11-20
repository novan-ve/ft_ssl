#pragma once

#include "commands.h"
#include "ftio.h"

#include <stdint.h>

#define RSA_VERSION 0
#define RSA_PUBLIC_EXPONENT 0x10001
#define RSA_BUFFER_SIZE 4096
#define RSA_MIN_PASS_LEN 4
#define RSA_MAX_PASS_LEN 1023
#define RSA_PRECISION 12

#define RSA_PRIV_HDR "-----BEGIN RSA PRIVATE KEY-----"
#define RSA_PRIV_FTR "-----END RSA PRIVATE KEY-----"
#define RSA_PROC_HDR "Proc-Type: 4,ENCRYPTED"
#define RSA_DEK_HDR "DEK-Info: DES-CBC,"
#define RSA_PUB_HDR "-----BEGIN PUBLIC KEY-----"
#define RSA_PUB_FTR "-----END PUBLIC KEY-----"
#define RSA_ASN1_OBJ_ID "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"

typedef enum {
    DER,
    PEM
} e_rsa_encoding;

typedef enum {
    PUBLIC,
    PRIVATE
} e_rsa_key_type;

typedef struct {
    e_rsa_key_type type;
    uint8_t version;
    uint64_t modulus;
    uint32_t pub_exp;
    uint64_t priv_exp;
    uint32_t prime1;
    uint32_t prime2;
    uint32_t exponent1;
    uint32_t exponent2;
    uint32_t coefficient;
} s_rsa_key;

typedef struct {
    char *rand_file;
    char *out_file;
    int out_fd;
} _s_genrsa_config;

typedef struct {
    char *inform;
    char *outform;
    s_io io;
    char *passin_arg;
    char *passout_arg;
    char passin[RSA_BUFFER_SIZE + 1];
    char passout[RSA_BUFFER_SIZE + 1];
    int des;
    int text;
    int noout;
    int modulus;
    int check;
    int pubin;
    int pubout;
} _s_rsa_config;

typedef struct {
    s_io io;
    char *key_file;
    int key_fd;
    int pubin;
    int decrypt;
    int cryptset;
    int hexdump;
} _s_rsautl_config;

int handle_genrsa(int argc, char *argv[], e_command command);
int handle_rsa(int argc, char *argv[], e_command command);
int handle_rsautl(int argc, char *argv[], e_command command);

int rsa_create_priv(const char *rand_file, s_rsa_key *key, e_command command);
int rsa_get_key(int fd, const char *filename, s_rsa_key *key, int pubin,
                char *passin, int passin_set, e_command command);

int rsa_print_priv(int fd, const char *filename, s_rsa_key *key,
                   e_rsa_encoding encoding, int des, char *pass, e_command command);
int rsa_print_pub(int fd, const char *filename, s_rsa_key *key,
                  e_rsa_encoding encoding, e_command command);
int rsa_print_text(int fd, s_rsa_key *key, e_command command);

char *rsa_read_password_enc(e_command command);
char *rsa_read_password_dec(const char *filename, e_command command);
int rsa_read_key(int fd, char *data, size_t len, int public, e_command command);
int rsa_check_key_data(char *data, int public);
int rsa_check_key(s_rsa_key *key, e_command command);
