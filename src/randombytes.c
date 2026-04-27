#include <sys/random.h>

void randombytes(unsigned char *buf, unsigned long long size)
{
    unsigned long long total = 0ull;

    while (total < size) {
        ssize_t n = getrandom(buf + total, size - total, 0);
        if (n <= 0) return;
        total += n;
    }
}