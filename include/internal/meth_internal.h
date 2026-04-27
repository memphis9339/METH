#ifndef METH_INTERNAL_H
#define METH_INTERNAL_H

#include <sys/types.h>

struct meth_connection {
    int fd;
    unsigned char shared_key[32];
};

struct meth_server {
    int fd;
};

struct meth_buffer {
    unsigned char* data;
    size_t len;
};

ssize_t meth_send(int fd, const void* buffer, size_t size);
ssize_t meth_recv(int fd, void *buf, size_t size);

#endif