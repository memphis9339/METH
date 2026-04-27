# meth

_Memphis Encrypted Transport Host. also methamphetamine :)_

Minimal encrypted TCP library in C, built on [TweetNaCl](https://tweetnacl.cr.yp.to/).

Provides ephemeral key exchange and encrypted send/recv over TCP. No TLS, no certificates — just X25519 + XSalsa20-Poly1305.

---

## How it works

On connect, both sides generate ephemeral X25519 keypairs and exchange public keys. A shared secret is derived with `crypto_box_beforenm`, then used to encrypt all subsequent messages with a random nonce per packet.

Each encrypted packet is framed as:

```
[4 bytes: length BE] [24 bytes: nonce] [ciphertext + 16 byte MAC]
```

> **Note:** The current key exchange is unauthenticated — it provides confidentiality but not protection against MITM. Server authentication (Noise NK pattern) is planned.

---

## API

```c
// Server
meth_server* meth_create_server(uint16_t port);
meth_connection* meth_accept(meth_server* server);
void meth_server_close(meth_server* server);

// Client
meth_connection* meth_secure_connect(const char* host, uint16_t port);

// Common
ssize_t meth_secure_send(meth_connection* conn, const void* buf, size_t size);
meth_buffer* meth_secure_recv(meth_connection* conn);
void meth_secure_close(meth_connection* conn);
```

`meth_buffer` holds the decrypted payload:

```c
typedef struct {
    unsigned char* data;
    size_t len;
} meth_buffer;
```

Free after use:

```c
free(buf->data);
free(buf);
```

---

## Example

**Server:**

```c
meth_server* server = meth_create_server(9339);
if (!server) return 1;

meth_connection* client = meth_accept(server);
meth_buffer* msg = meth_secure_recv(client);

printf("received: %.*s\n", (int)msg->len, msg->data);

free(msg->data);
free(msg);
meth_secure_close(client);
meth_server_close(server);
```

**Client:**

```c
meth_connection* conn = meth_secure_connect("127.0.0.1", 9339);
if (!conn) return 1;

meth_secure_send(conn, "hello", 5);
meth_secure_close(conn);
```

---

## Build

```bash
cmake -B build
cmake --build build
```

Requires: CMake 3.10+, C11 compiler, Brain.  
TweetNaCl is vendored in `external/tweetnacl`.

---

## Project structure

```
├── include/            # Public headers (meth.h, crypto.h, byteorder.h)
│   └── internal/       # Internal headers (not part of public API)
├── src/                # Library source
├── external/           # Vendored TweetNaCl
└── test/               # Tests and usage examples
```

---

## License

MIT
