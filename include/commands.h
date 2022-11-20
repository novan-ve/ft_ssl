#pragma once

typedef enum {
    md5,
    sha1,
    sha256,
    base64,
    des,
    des_cbc,
    des_ecb,
    genrsa,
    rsa,
    rsautl
} e_command;

typedef struct {
    const char  *str;
    int (*handler)(int, char*[], e_command);
} s_command;

extern s_command commands[10];
