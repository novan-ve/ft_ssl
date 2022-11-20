#pragma once

#include <stddef.h>

#include "commands.h"

typedef char* (*fn_digest_str)(char*, size_t, int);
typedef char* (*fn_digest_fd)(unsigned int, int, int);

typedef struct {
    fn_digest_str digest_str;
    fn_digest_fd digest_fd;
} _s_digest_fn;

typedef struct {
    int echo;
    int quiet;
    int reverse;
    char *str;
} _s_digest_config;

int handle_digest(int argc, char *argv[], e_command command);
