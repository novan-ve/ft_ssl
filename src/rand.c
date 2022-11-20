#include "rand.h"
#include "libft.h"
#include "ftmath.h"

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int rand_fill(void *d, size_t n)
{
    size_t bytes_read = 0;
    size_t count = 0;
    int fd;

    if (n == 0) {
        return (0);
    }
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return (-1);
    }
    for (size_t pos = 0; pos < n; pos += RAND_BUFFER_SIZE) {
        count = (n - pos > RAND_BUFFER_SIZE) ? RAND_BUFFER_SIZE : n - pos;
        bytes_read = read(fd, d + pos, count);
        if (bytes_read < count) {
            close(fd);
            return (-1);
        }
    }
    close(fd);
    return (0);
}

int random_init_seed(const char *seed_file, uint32_t *x, uint32_t *y)
{
    ssize_t bytes_read = 1;
    size_t i = 0;
    uint8_t c;
    int fd;

    if (!x || !y) {
        errno = EINVAL;
        return (0);
    }
    *x = 0, *y = 0;
    if (seed_file) {
        if ((fd = open(seed_file, O_RDONLY)) < 0) {
            return (0);
        }
        for (i = 0; i < sizeof(*x) && bytes_read; i++) {
            bytes_read = read(fd, &c, 1);
            if (bytes_read < 0) {
                close(fd);
                return (0);
            }
            *x |= c << ((sizeof(*x) - 1 - i) * 8);
        }
        close(fd);
    }
    if ((fd = open("/dev/random", O_RDONLY)) < 0) {
        return (0);
    }
    while (i < sizeof(*x)) {
        if (read(fd, &c, 1) <= 0) {
            close(fd);
            return (0);
        }
        *x |= c << ((sizeof(*x) - 1 - i) * 8);
        i++;
    }
    for (i = 0; i < sizeof(*y); i++) {
        if (read(fd, &c, 1) <= 0) {
            close(fd);
            return (0);
        }
        *y |= c << ((sizeof(*y) - 1 - i) * 8);
    }
    close(fd);
    return (1);
}

uint32_t srandom_nb(const char *seed_file)
{
    static uint32_t x = 0;
    static uint32_t inc = 0;
    uint32_t mod = 0x7FFFFFFF;
    uint32_t mult = 0x41A7;
    uint64_t tmp = 0;

    if (!x) {
        if (!random_init_seed(seed_file, &x, &inc)) {
            return (0);
        }
        while (x >= mod) {
            x >>= 1;
        }
        while (inc >= mod) {
            inc >>= 1;
        }
    }
    tmp = ((uint64_t)x * mult + inc) % mod;
    x = tmp;
    return (x);
}

uint32_t srandom_prime(const char *seed_file, int precision, int print)
{
    uint32_t res;

    while (1) {
        if (print) {
            ft_dprintf(STDERR_FILENO, ".");
        }
        res = srandom_nb(seed_file);
        if (!res) {
            break;
        }
        res |= (3 << 30);
        if (is_prime(res, precision, print)) {
            break;
        }
    }
    ft_dprintf(STDERR_FILENO, "\n");
    return (res);
}
