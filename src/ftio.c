#include "ftio.h"
#include "fterror.h"

#include <fcntl.h>
#include <errno.h>

int set_in_fd(s_io *io, const char *command)
{
    if (io->in_file) {
        io->in_fd = open(io->in_file, O_RDONLY);
        if (io->in_fd < 0) {
            error_file(command, io->in_file);
            return (-1);
        }
    }
    else {
        io->in_fd = STDIN_FILENO;
    }
    return (0);
}

int set_out_fd(s_io *io, const char *command)
{
    if (io->out_file) {
        io->out_fd = open(io->out_file, O_WRONLY|O_CREAT|O_TRUNC,
            S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
        if (io->out_fd < 0) {
            error_file(command, io->out_file);
            if (io->in_fd != STDIN_FILENO && close(io->in_fd) < 0) {
                error_file(command, io->in_file);
            }
            return (-1);
        }
    }
    else {
        io->out_fd = STDOUT_FILENO;
    }
    return (0);
}

int close_in_fd(s_io *io, const char *command)
{
    if (io->in_fd != STDIN_FILENO && close(io->in_fd) < 0) {
        error_file(command, io->in_file);
        return (-1);
    }
    return (0);
}

int close_out_fd(s_io *io, const char *command)
{
    if (io->out_fd != STDOUT_FILENO && close(io->out_fd) < 0) {
        error_file(command, io->out_file);
        return (-1);
    }
    return (0);
}

int set_fds(s_io *io, const char *command)
{
    if (set_in_fd(io, command) < 0) {
        return (-1);
    }
    if (set_out_fd(io, command) < 0) {
        return (-1);
    }
    return (0);
}

int close_fds(s_io *io, const char *command)
{
    int ret = 0;

    if (close_in_fd(io, command) < 0) {
        ret = -1;
    }
    if (close_out_fd(io, command) < 0) {
        ret = -1;
    }
    return (ret);
}

ssize_t read_full_buffer(int fd, char *buf, ssize_t len) {
    ssize_t count = 0;
    ssize_t bytes_read = 0;

    if (!buf) {
        errno = EINVAL;
        return (-1);
    }
    while (count < len - 1) {
        bytes_read = read(fd, buf, len - 1 - count);
        if (bytes_read < 0) {
            return (-1);
        }
        if (!bytes_read) {
            break;
        }
        count += bytes_read;
    }
    buf[count] = '\0';

    return (count);
}
