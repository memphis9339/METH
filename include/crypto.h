#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

#define crypto_box_MACBYTES 16
typedef unsigned char u8;
typedef unsigned long long u64;

typedef struct {
    u8 pk[32];
    u8 sk[32];
} meth_keypair;

int meth_crypto_genkeys(meth_keypair* kp);
int meth_crypto_keyexchange(int fd, u8* out);

int meth_crypto_encrypt(
    const u8* plain,
    u8* cipher,
    size_t plain_len,
    size_t cipher_c,
    const u8* key
);
int meth_crypto_decrypt(
    u8* plaintext_out,
    size_t plaintext_out_len,
    const u8* ciphertext,
    unsigned long long cipher_len,
    const u8* key);


#endif