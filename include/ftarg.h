#pragma once

#include <stddef.h>

typedef struct {
    const char id;
    const char letter;
    const char *name;
    int has_arg;
} s_ftarg_opt;

extern char *optarg;
extern char *optval;
extern int optind;

int ftarg_getopt(int argc, char *const argv[],
                 const s_ftarg_opt *options, size_t optcount);
