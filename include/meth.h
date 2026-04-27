#ifndef METH_H
#define METH_H

#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define METH_MAX_PACKET 65536

typedef struct meth_connection meth_connection;
typedef struct meth_buffer meth_buffer;
typedef struct meth_server meth_server;

meth_connection* meth_secure_connect(const char* host, uint16_t port);
meth_connection* meth_accept(meth_server* server);
void meth_server_close(meth_server* server);

meth_server* meth_create_server(uint16_t port);

ssize_t meth_secure_send(meth_connection* conn, const void* buf, size_t size);
meth_buffer* meth_secure_recv(meth_connection* conn);
void meth_secure_close(meth_connection* conn);

#endif