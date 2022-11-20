#pragma once

#include <unistd.h>

typedef struct
{
    char *in_file;
    char *out_file;
    int in_fd;
    int out_fd;
} s_io;

int set_fds(s_io *io, const char *command);
int set_in_fd(s_io *io, const char *command);
int set_out_fd(s_io *io, const char *command);

int close_fds(s_io *io, const char *command);
int close_in_fd(s_io *io, const char *command);
int close_out_fd(s_io *io, const char *command);

ssize_t read_full_buffer(int fd, char *buf, ssize_t len);
