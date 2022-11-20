#pragma once

#define PROGRAM_NAME "ft_ssl"

#define ARG_NO_VALUE 0
#define ARG_MISSING_VALUE 1
#define ARG_UNRECOGNIZED 2
#define ARG_EXTRA 3

#define ERR_MALLOC "malloc failed"
#define ERR_INPUT_OVERFLOW "Converting input size will cause output size to overflow"
#define ERR_GETPASS "getpass failed"
#define ERR_MODULAR_INVERSE "modular inverse failed"

#define ERR_PUB_CHECK "Only private keys can be checked"
#define ERR_PRIV_KEY "unable to load Private Key"
#define ERR_PUB_KEY "unable to load Public Key"

#define ERR_RSA_PRIME_1 "p not prime"
#define ERR_RSA_PRIME_2 "q not prime"
#define ERR_RSA_MODULUS "n does not equal p q"
#define ERR_RSA_PRIV_EXP "d e not congruent to 1"
#define ERR_RSA_EXP_1 "dmp1 not congruent to d"
#define ERR_RSA_EXP_2 "dmq1 not congruent to d"
#define ERR_RSA_COEFFICIENT "iqmp not inverse of q"
#define ERR_RSA_NO_INVERSE "no inverse"

void error_arg(const char *command, const char *opt, int error_code);
void error_file(const char *command, const char *filename);
void error_str(const char *command, const char *error_msg);
void error_errno(const char *command, const char *error_msg, int errnum);
void error_other(const char *command);
