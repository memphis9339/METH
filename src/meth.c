#include <sys/socket.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <tweetnacl.h>
#include <randombytes.h>
#include <meth.h>
#include <byteorder.h>
#include <crypto.h>

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

static int meth_make_ipv4_addr(struct sockaddr_in* out, const char* ip, int port) 
{
    if (!out || !ip) return -1;

    memset(out, 0, sizeof(*out));

    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, ip, &out->sin_addr) != 1) {
        return -1;
    }

    return 0;
}

ssize_t meth_recv(int fd, void *buf, size_t size)
{
    if (fd < 0 || !buf || size == 0)
        return -1;

    size_t total = 0;

    while (total < size) {
        ssize_t r = recv(fd, (char *)buf + total, size - total, 0);

        if (r == 0 || r < 0)
            return -1; 

        total += (size_t)r;
    }

    return 0;
}

ssize_t meth_send(int fd, const void* buffer, size_t size)
{
    if (fd < 0 || !buffer || size == 0)
        return -1;

    size_t sent = 0;

    while (sent < size) {
        ssize_t r = send(fd, (const char*)buffer + sent, size - sent, 0);

        if (r <= 0)
            return -1;

        sent += (size_t)r;
    }

    return sent;
}

static int meth_connect(const char* host, uint16_t port, int* out)
{
    if (!host || !out)
        return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    if (meth_make_ipv4_addr(&addr, host, port) != 0) {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    *out = fd;
    return 0;
}

meth_server* meth_create_server(uint16_t port)
{
    meth_server* server = calloc(1, sizeof(meth_server));
    if (!server) return NULL;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) { 
        free(server); 
        return NULL; 
    }

    struct sockaddr_in addr;
    if (meth_make_ipv4_addr(&addr, "0.0.0.0", port) != 0) {
        close(fd); 
        free(server); 
        return NULL;
    }

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd); 
        free(server); 
        return NULL;
    }

    if (listen(fd, 10) != 0) {
        close(fd);
        free(server); 
        return NULL;
    }

    server->fd = fd;
    return server;
}

meth_connection* meth_secure_connect(const char* host, uint16_t port) 
{
    if (!host) return NULL;

    meth_connection* conn = calloc(1, sizeof(meth_connection));

    int fd;
    if (meth_connect(host, port, &fd) == -1) {
        free(conn);
        return NULL;
    }

    unsigned char shared_key[32];
    if (meth_crypto_keyexchange(fd, shared_key) != 0) {
        close(fd);
        free(conn);
        return NULL;
    }

    conn->fd = fd;
    memcpy(conn->shared_key, shared_key, 32);

    return conn;
}

meth_connection* meth_accept(meth_server* server)
{
    if (!server || server->fd < 0)
        return NULL;

    meth_connection* conn = calloc(1, sizeof(meth_connection));

    int socket = accept(server->fd, NULL, NULL);
    if (socket == -1) {
        free(conn);
        return NULL;
    }

    unsigned char shared_key[32];
    if (meth_crypto_keyexchange(socket, shared_key) != 0) {
        close(socket);
        free(conn);
        return NULL;
    }

    conn->fd = socket;
    memcpy(conn->shared_key, shared_key, 32);

    return conn;
}

ssize_t meth_secure_send(meth_connection* conn, const void* buffer, size_t size)
{
    if (!conn || !buffer || conn->fd == -1)
        return -1;

    const unsigned char* data = buffer;
    size_t max_cipher = size + 16 + 24;

    unsigned char* tmp = malloc(max_cipher + 4);
    if (!tmp) return -1;

    int res = meth_crypto_encrypt(
        data,
        tmp + 4,
        size,
        max_cipher,
        conn->shared_key
    );

    if (res < 0) {
        free(tmp);
        return -1;
    }
        
    write_u32_be((uint32_t)res, tmp);

    ssize_t sent = meth_send(conn->fd, tmp, res + 4);
    free(tmp);
    return sent;
}       

meth_buffer* meth_secure_recv(meth_connection* conn)
{
    if (!conn || conn->fd == -1)
        return NULL;

    unsigned char header[4];
    if (meth_recv(conn->fd, header, 4) != 0)
        return NULL;

    uint32_t length = read_u32_be(header);
    if (length < 24 + 16 || length > METH_MAX_PACKET)
        return NULL;

    unsigned char* payload = (unsigned char*)malloc(length);
    if (!payload)
        return NULL;

    if (meth_recv(conn->fd, payload, length) != 0) {
        free(payload);
        return NULL;
    }

    size_t plain_buf_len = length;
    unsigned char* plaintext_buf = (unsigned char*)malloc(plain_buf_len);
    if (!plaintext_buf) {
        free(payload);
        return NULL;
    }

    int dec_len = meth_crypto_decrypt(
        plaintext_buf,
        plain_buf_len,
        payload,
        length,
        conn->shared_key
    );

    if (dec_len < 0) {
        free(payload);
        free(plaintext_buf);
        return NULL;
    }

    size_t plain_len = (size_t)dec_len;
    meth_buffer* buf = calloc(1, sizeof(meth_buffer));

    if (!buf) { 
        free(payload);
        free(plaintext_buf); 
        return NULL; 
    }

    unsigned char* out = malloc(plain_len);
    if (!out) {
        free(payload);
        free(plaintext_buf); 
        return NULL; 
    }
    
    memcpy(out, plaintext_buf + 32, plain_len);
    free(plaintext_buf);
    free(payload);

    buf->data = out;
    buf->len = plain_len;
    return buf;
}

void meth_server_close(meth_server* server)
{
    if (!server) return;
    if (server->fd != -1) close(server->fd);
    free(server);
}

void meth_secure_close(meth_connection* conn) {
    if (!conn) return;
    if (conn->fd != -1) close(conn->fd);
    
    memset(conn->shared_key, 0, 32); 
    free(conn);
}
