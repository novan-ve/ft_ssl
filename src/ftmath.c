#include "ftmath.h"
#include "rand.h"
#include "libft.h"

size_t intlen(size_t x)
{
    size_t len = 0;

    for (size_t i = sizeof(size_t); i > 1; i--) {
        if (((x >> (i - 1) * 8) & 0xFF) != 0) {
            break;
        }
        len++;
    }
    return (sizeof(size_t) - len);
}

size_t bitlen(size_t x)
{
    size_t len = 0;

    while (x) {
        x >>= 1;
        len++;
    }
    return (len);
}

uint64_t modular_inverse(uint64_t x, uint64_t y)
{
    uint64_t a = 0;
    uint64_t b = 0;
    uint64_t n = x;
    long tmp = 0;
    long t1 = 0;
    long t2 = 1;
 
    while (y > 0)
    {
        a = n / y;
        b = n - a * y;
        n = y;
        y = b;
 
        tmp = t1 - a * t2;
        t1 = t2;
        t2 = tmp;
    }
    if (n == 1) {
        if (t1 < 0) {
            return ((uint64_t)(t1 + x));
        }
        return ((uint64_t)t1);
    }
    return (0);
}

uint64_t add_mod(uint64_t x, uint64_t y, uint64_t p)
{
    x = x % p;
    y = y % p;
    if (x >= p - y) {
        return (x - (p - y));
    }
    return (x + y);
}

uint64_t mult_mod(uint64_t x, uint64_t y, uint64_t p)
{
    uint64_t res = 0;

    for (; y > 0; y >>= 1) {
        if (y % 2 == 1) {
            res = add_mod(res, x, p);
        }
        x = add_mod(x, x, p);
    }
    return (res);
}

uint64_t power_mod(uint64_t x, uint64_t y, uint64_t p)
{
    uint64_t res = 1;

    x = x % p;
    for (; y > 0; y >>= 1) {
        if (y % 2 == 1) {
            res = mult_mod(res, x, p);
        }
        x = mult_mod(x, x, p);
    }
    return (res);
}

int miller_rabin(uint64_t n, uint64_t d)
{
    uint64_t a = 2 + srandom_nb(NULL) % (n - 4);
    uint64_t x = power_mod(a, d, n);

    if (x == 1 || x == n - 1) {
        return (1);
    }
    while (d != n - 1) {
        x = (x * x) % n;
        d *= 2;
        if (x == 1) {
            return (0);
        }
        if (x == n - 1) {
            return (1);
        }
    }
    return (0);
}

int is_prime(uint64_t n, int k, int print)
{
    uint64_t d;

    if (n <= 1 || n == 4) {
        return (0);
    }
    if (n == 2 || n == 3) {
        return (1);
    }
    d = n - 1;
    while (d % 2 == 0) {
        d /= 2;
    }
    for (int i = 0; i < k; i++) {
        if (!miller_rabin(n, d)) {
            return (0);
        }
        if (print) {
            ft_dprintf(STDERR_FILENO, "+");
        }
    }
    return (1);
}
