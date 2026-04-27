#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

typedef struct {
    unsigned char pk[32];
    unsigned char sk[32];
} meth_keypair;

int meth_crypto_genkeys(meth_keypair* kp);
int meth_crypto_keyexchange(int fd, unsigned char* out);

int meth_crypto_encrypt(
    const unsigned char* plain,
    unsigned char* cipher,
    size_t plain_len,
    size_t cipher_c,
    const unsigned char* key
);
int meth_crypto_decrypt(
    unsigned char* plaintext_out,
    size_t plaintext_out_len,
    const unsigned char* ciphertext,
    unsigned long long cipher_len,
    const unsigned char* key);


#endif