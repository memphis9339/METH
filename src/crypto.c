#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>

#include <crypto.h>
#include <randombytes.h>
#include <internal/meth_internal.h>
#include <tweetnacl.h>

static unsigned char* meth_align_plaintext(const unsigned char* text, size_t text_len, size_t* out_len)
{
    *out_len = text_len + 32;
    unsigned char* padded = (unsigned char*)malloc(*out_len);
    if (!padded) return NULL;

    memset(padded, 0, 32);
    memcpy(padded + 32, text, text_len);

    return padded;
}

int meth_crypto_genkeys(meth_keypair* kp)
{
    if (!kp)
        return -1;

    crypto_box_keypair(kp->pk, kp->sk);
    return 0;
}

int meth_crypto_keyexchange(int fd, unsigned char* out)
{
    meth_keypair kp = {0};
    if (meth_crypto_genkeys(&kp) == -1)
        return -1;

    if (meth_send(fd, kp.pk, sizeof(kp.pk)) == -1)
        return -1;

    unsigned char peer_pk[32];
    int r = meth_recv(fd, peer_pk, sizeof(peer_pk));

    if (r == -1)
        return -1;

    if (crypto_box_beforenm(out, peer_pk, kp.sk) != 0) {
        memset(kp.sk, 0, sizeof(kp.sk));
        memset(peer_pk, 0, sizeof(peer_pk));
        return -1;
    }

    memset(kp.sk, 0, sizeof(kp.sk));
    memset(peer_pk, 0, sizeof(peer_pk));
    return 0;
}

int meth_crypto_encrypt(
    const unsigned char* in,
    unsigned char* out,
    size_t in_len,
    size_t out_cap,
    const unsigned char* key)
{
    if (!in || !out || !key)
        return -1;

    size_t need = 24 + in_len + 16;
    if (out_cap < need)
        return -1;

    size_t buf_len;
    unsigned char* buf = meth_align_plaintext(in, in_len, &buf_len);
    if (!buf)
        return -1;

    unsigned char* enc = (unsigned char*)malloc(buf_len);
    if (!enc) {
        free(buf);
        return -1;
    }
    memset(enc, 0, buf_len);

    unsigned char nonce[24];
    randombytes(nonce, 24);

    if (crypto_box_afternm(enc, buf, buf_len, nonce, key) != 0) {
        free(buf);
        free(enc);
        return -1;
    }

    memcpy(out, nonce, 24);
    memcpy(out + 24, enc + 16, in_len + 16);

    free(buf);
    free(enc);
    return (int)need;
}

int meth_crypto_decrypt(
    unsigned char* out,
    size_t out_cap,
    const unsigned char* in,
    unsigned long long in_len,
    const unsigned char* key)
{
    if (!out || !in || !key)
        return -1;
    
    if (in_len < 24 + 16)
        return -1;

    const unsigned char* nonce = in;
    const unsigned char* body = in + 24;
    unsigned long long body_len = in_len - 24;

    size_t buf_len = body_len + 16;
    unsigned char* buf = (unsigned char*)malloc(buf_len);
    if (!buf)
        return -1;

    memset(buf, 0, 16);
    memcpy(buf + 16, body, body_len);

    size_t plain_len = body_len - 16;
    if (out_cap < buf_len) {
        free(buf);
        return -1;
    }

    if (crypto_box_open_afternm(out, buf, buf_len, nonce, key) != 0) {
        memset(out, 0, plain_len + 32);
        free(buf);
        return -1;
    }

    free(buf);
    return (int)plain_len;
}