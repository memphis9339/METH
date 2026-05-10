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
    *out_len = text_len + crypto_box_ZEROBYTES;
    unsigned char* padded = (unsigned char*)malloc(*out_len);
    if (!padded) return NULL;

    memset(padded, 0, crypto_box_ZEROBYTES);
    memcpy(padded + crypto_box_ZEROBYTES, text, text_len);

    return padded;
}

int meth_crypto_genkeys(meth_keypair* kp)
{
    if (!kp) return -1;

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

    unsigned char peer_pk[crypto_box_PUBLICKEYBYTES];
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

    size_t need = crypto_box_NONCEBYTES + in_len + crypto_box_MACBYTES;
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

    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes(nonce, crypto_box_NONCEBYTES);

    if (crypto_box_afternm(enc, buf, buf_len, nonce, key) != 0) {
        free(buf);
        free(enc);
        return -1;
    }

    memcpy(out, nonce, crypto_box_NONCEBYTES);
    memcpy(out + crypto_box_NONCEBYTES, enc + crypto_box_MACBYTES, in_len + crypto_box_MACBYTES);

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
    
    if (in_len < crypto_box_NONCEBYTES + crypto_box_MACBYTES)
        return -1;

    const unsigned char* nonce = in;
    const unsigned char* body = in + crypto_box_NONCEBYTES;
    unsigned long long body_len = in_len - crypto_box_NONCEBYTES;

    size_t buf_len = body_len + crypto_box_MACBYTES;
    unsigned char* buf = (unsigned char*)malloc(buf_len);
    if (!buf)
        return -1;

    memset(buf, 0, crypto_box_MACBYTES);
    memcpy(buf + crypto_box_MACBYTES, body, body_len);

    size_t plain_len = body_len - crypto_box_MACBYTES;
    if (out_cap < buf_len) {
        free(buf);
        return -1;
    }

    if (crypto_box_open_afternm(out, buf, buf_len, nonce, key) != 0) {
        memset(out, 0, plain_len + crypto_box_ZEROBYTES);
        free(buf);
        return -1;
    }

    free(buf);
    return (int)plain_len;
}