/*
 * Copyright (c) 2002 Bob Beck <beck@openbsd.org>
 * Copyright (c) 2002 Theo de Raadt
 * Copyright (c) 2002 Markus Friedl
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#if (defined(__unix__) || defined(unix)) && !defined(USG) && \
        (defined(OpenBSD) || defined(__FreeBSD__))
# include <sys/param.h>
# if (OpenBSD >= 200112) || ((__FreeBSD_version >= 470101 && __FreeBSD_version < 500000) || __FreeBSD_version >= 500041)
#  define HAVE_CRYPTODEV
# endif
# if (OpenBSD >= 200110)
#  define HAVE_SYSLOG_R
# endif
#endif

#ifndef HAVE_CRYPTODEV

void ENGINE_load_cryptodev(void)
{
    /* This is a NOP on platforms without /dev/crypto */
    return;
}

#else

# include <sys/types.h>
# include <crypto/cryptodev.h>
# include <openssl/dh.h>
# include <openssl/dsa.h>
# include <openssl/err.h>
# include <openssl/rsa.h>
# include <crypto/ecdsa/ecs_locl.h>
# include <crypto/ecdh/ech_locl.h>
# include <crypto/ec/ec_lcl.h>
# include <crypto/ec/ec.h>
# include <sys/ioctl.h>
# include <errno.h>
# include <stdio.h>
# include <unistd.h>
# include <fcntl.h>
# include <stdarg.h>
# include <syslog.h>
# include <errno.h>
# include <string.h>
# include "eng_cryptodev_ec.h"

struct dev_crypto_state {
    struct session_op d_sess;
    int d_fd;
    unsigned char *aad;
    unsigned int aad_len;
    unsigned int len;
# ifdef USE_CRYPTODEV_DIGESTS
    char dummy_mac_key[HASH_MAX_LEN];
    unsigned char digest_res[HASH_MAX_LEN];
    char *mac_data;
    int mac_len;
# endif
};

static u_int32_t cryptodev_asymfeat = 0;

static int get_asym_dev_crypto(void);
static int open_dev_crypto(void);
static int get_dev_crypto(void);
static int get_cryptodev_ciphers(const int **cnids);
# ifdef USE_CRYPTODEV_DIGESTS
static int get_cryptodev_digests(const int **cnids);
# endif
static int cryptodev_usable_ciphers(const int **nids);
static int cryptodev_usable_digests(const int **nids);
static int cryptodev_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t inl);
static int cryptodev_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                              const unsigned char *iv, int enc);
static int cryptodev_cleanup(EVP_CIPHER_CTX *ctx);
static int cryptodev_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                                    const int **nids, int nid);
static int cryptodev_engine_digests(ENGINE *e, const EVP_MD **digest,
                                    const int **nids, int nid);
static int bn2crparam(const BIGNUM *a, struct crparam *crp);
static int crparam2bn(struct crparam *crp, BIGNUM *a);
static void zapparams(struct crypt_kop *kop);
static int cryptodev_asym(struct crypt_kop *kop, int rlen, BIGNUM *r,
                          int slen, BIGNUM *s);

static int cryptodev_bn_mod_exp(BIGNUM *r, const BIGNUM *a,
                                const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                                BN_MONT_CTX *m_ctx);
static int cryptodev_rsa_nocrt_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                                       BN_CTX *ctx);
static int cryptodev_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                                 BN_CTX *ctx);
static DSA_SIG *cryptodev_dsa_do_sign(const unsigned char *dgst, int dlen,
                                      DSA *dsa);
static int cryptodev_dsa_verify(const unsigned char *dgst, int dgst_len,
                                DSA_SIG *sig, DSA *dsa);
static int cryptodev_dh_compute_key(unsigned char *key, const BIGNUM *pub_key,
                                    DH *dh);
static int cryptodev_ctrl(ENGINE *e, int cmd, long i, void *p,
                          void (*f) (void));
void ENGINE_load_cryptodev(void);
const EVP_CIPHER cryptodev_aes_128_cbc_hmac_sha1;
const EVP_CIPHER cryptodev_aes_256_cbc_hmac_sha1;

inline int spcf_bn2bin(BIGNUM *bn, unsigned char **bin, int *bin_len)
{
    int len;
    unsigned char *p;

    len = BN_num_bytes(bn);

    if (!len)
        return -1;

    p = malloc(len);
    if (!p)
        return -1;

    BN_bn2bin(bn, p);

    *bin = p;
    *bin_len = len;

    return 0;
}

inline int spcf_bn2bin_ex(BIGNUM *bn, unsigned char **bin, int *bin_len)
{
    int len;
    unsigned char *p;

    len = BN_num_bytes(bn);

    if (!len)
        return -1;

    if (len < *bin_len)
        p = malloc(*bin_len);
    else
        p = malloc(len);

    if (!p)
        return -ENOMEM;

    if (len < *bin_len) {
        /* place padding */
        memset(p, 0, (*bin_len - len));
        BN_bn2bin(bn, p + (*bin_len - len));
    } else {
        BN_bn2bin(bn, p);
    }

    *bin = p;
    if (len >= *bin_len)
        *bin_len = len;

    return 0;
}

/**
 * Convert an ECC F2m 'b' parameter into the 'c' parameter.
 *Inputs:
 * q, the curve's modulus
 * b, the curve's b parameter
 * (a bignum for b, a buffer for c)
 * Output:
 * c, written into bin, right-adjusted to fill q_len bytes.
 */
static int
eng_ec_compute_cparam(const BIGNUM *b, const BIGNUM *q,
                      unsigned char **bin, int *bin_len)
{
    BIGNUM *c = BN_new();
    BIGNUM *exp = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    int m = BN_num_bits(q) - 1;
    int ok = 0;

    if (!c || !exp || !ctx || *bin)
        goto err;

    /*
     * We have to compute c, where b = c^4, i.e., the fourth root of b.
     * The equation for c is c = b^(2^(m-2))
     * Compute exp = 2^(m-2)
     * (1 << x) == 2^x
     * and then compute c = b^exp
     */
    BN_lshift(exp, BN_value_one(), m - 2);
    BN_GF2m_mod_exp(c, b, exp, q, ctx);
    /* Store c */
    spcf_bn2bin_ex(c, bin, bin_len);
    ok = 1;
 err:
    if (ctx)
        BN_CTX_free(ctx);
    if (c)
        BN_free(c);
    if (exp)
        BN_free(exp);
    return ok;
}

static const ENGINE_CMD_DEFN cryptodev_defns[] = {
    {0, NULL, NULL, 0}
};

static struct {
    int id;
    int nid;
    int ivmax;
    int keylen;
    int mackeylen;
} ciphers[] = {
    {
        CRYPTO_ARC4, NID_rc4, 0, 16, 0
    },
    {
        CRYPTO_DES_CBC, NID_des_cbc, 8, 8, 0
    },
    {
        CRYPTO_3DES_CBC, NID_des_ede3_cbc, 8, 24, 0
    },
    {
        CRYPTO_AES_CBC, NID_aes_128_cbc, 16, 16, 0
    },
    {
        CRYPTO_AES_CBC, NID_aes_192_cbc, 16, 24, 0
    },
    {
        CRYPTO_AES_CBC, NID_aes_256_cbc, 16, 32, 0
    },
# ifdef CRYPTO_AES_CTR
    {
        CRYPTO_AES_CTR, NID_aes_128_ctr, 14, 16,
    },
    {
        CRYPTO_AES_CTR, NID_aes_192_ctr, 14, 24,
    },
    {
        CRYPTO_AES_CTR, NID_aes_256_ctr, 14, 32,
    },
# endif
    {
        CRYPTO_BLF_CBC, NID_bf_cbc, 8, 16, 0
    },
    {
        CRYPTO_CAST_CBC, NID_cast5_cbc, 8, 16, 0
    },
    {
        CRYPTO_SKIPJACK_CBC, NID_undef, 0, 0, 0
    },
    {
        CRYPTO_TLS10_AES_CBC_HMAC_SHA1, NID_aes_128_cbc_hmac_sha1, 16, 16, 20
    },
    {
        CRYPTO_TLS10_AES_CBC_HMAC_SHA1, NID_aes_256_cbc_hmac_sha1, 16, 32, 20
    },
    {
        0, NID_undef, 0, 0, 0
    },
};

# ifdef USE_CRYPTODEV_DIGESTS
static struct {
    int id;
    int nid;
    int keylen;
} digests[] = {
    {
        CRYPTO_MD5_HMAC, NID_hmacWithMD5, 16
    },
    {
        CRYPTO_SHA1_HMAC, NID_hmacWithSHA1, 20
    },
    {
        CRYPTO_RIPEMD160_HMAC, NID_ripemd160, 16
        /* ? */
    },
    {
        CRYPTO_MD5_KPDK, NID_undef, 0
    },
    {
        CRYPTO_SHA1_KPDK, NID_undef, 0
    },
    {
        CRYPTO_MD5, NID_md5, 16
    },
    {
        CRYPTO_SHA1, NID_sha1, 20
    },
    {
        0, NID_undef, 0
    },
};
# endif

/*
 * Return a fd if /dev/crypto seems usable, 0 otherwise.
 */
static int open_dev_crypto(void)
{
    static int fd = -1;

    if (fd == -1) {
        if ((fd = open("/dev/crypto", O_RDWR, 0)) == -1)
            return (-1);
        /* close on exec */
        if (fcntl(fd, F_SETFD, 1) == -1) {
            close(fd);
            fd = -1;
            return (-1);
        }
    }
    return (fd);
}

static int get_dev_crypto(void)
{
    int fd, retfd;

    if ((fd = open_dev_crypto()) == -1)
        return (-1);
# ifndef CRIOGET_NOT_NEEDED
    if (ioctl(fd, CRIOGET, &retfd) == -1)
        return (-1);

    /* close on exec */
    if (fcntl(retfd, F_SETFD, 1) == -1) {
        close(retfd);
        return (-1);
    }
# else
    retfd = fd;
# endif
    return (retfd);
}

static void put_dev_crypto(int fd)
{
# ifndef CRIOGET_NOT_NEEDED
    close(fd);
# endif
}

/* Caching version for asym operations */
static int get_asym_dev_crypto(void)
{
    static int fd = -1;

    if (fd == -1)
        fd = get_dev_crypto();
    return fd;
}

/*
 * Find out what ciphers /dev/crypto will let us have a session for.
 * XXX note, that some of these openssl doesn't deal with yet!
 * returning them here is harmless, as long as we return NULL
 * when asked for a handler in the cryptodev_engine_ciphers routine
 */
static int get_cryptodev_ciphers(const int **cnids)
{
    static int nids[CRYPTO_ALGORITHM_MAX];
    struct session_op sess;
    int fd, i, count = 0;

    if ((fd = get_dev_crypto()) < 0) {
        *cnids = NULL;
        return (0);
    }
    memset(&sess, 0, sizeof(sess));
    sess.key = (caddr_t) "123456789abcdefghijklmno";
    sess.mackey = (caddr_t) "123456789ABCDEFGHIJKLMNO";

    for (i = 0; ciphers[i].id && count < CRYPTO_ALGORITHM_MAX; i++) {
        if (ciphers[i].nid == NID_undef)
            continue;
        sess.cipher = ciphers[i].id;
        sess.keylen = ciphers[i].keylen;
        sess.mackeylen = ciphers[i].mackeylen;

        if (ioctl(fd, CIOCGSESSION, &sess) != -1 &&
            ioctl(fd, CIOCFSESSION, &sess.ses) != -1)
            nids[count++] = ciphers[i].nid;
    }
    put_dev_crypto(fd);

    if (count > 0)
        *cnids = nids;
    else
        *cnids = NULL;
    return (count);
}

# ifdef USE_CRYPTODEV_DIGESTS
/*
 * Find out what digests /dev/crypto will let us have a session for.
 * XXX note, that some of these openssl doesn't deal with yet!
 * returning them here is harmless, as long as we return NULL
 * when asked for a handler in the cryptodev_engine_digests routine
 */
static int get_cryptodev_digests(const int **cnids)
{
    static int nids[CRYPTO_ALGORITHM_MAX];
    struct session_op sess;
    int fd, i, count = 0;

    if ((fd = get_dev_crypto()) < 0) {
        *cnids = NULL;
        return (0);
    }
    memset(&sess, 0, sizeof(sess));
    sess.mackey = (caddr_t) "123456789abcdefghijklmno";
    for (i = 0; digests[i].id && count < CRYPTO_ALGORITHM_MAX; i++) {
        if (digests[i].nid == NID_undef)
            continue;
        sess.mac = digests[i].id;
        sess.mackeylen = digests[i].keylen;
        sess.cipher = 0;
        if (ioctl(fd, CIOCGSESSION, &sess) != -1 &&
            ioctl(fd, CIOCFSESSION, &sess.ses) != -1)
            nids[count++] = digests[i].nid;
    }
    put_dev_crypto(fd);

    if (count > 0)
        *cnids = nids;
    else
        *cnids = NULL;
    return (count);
}
# endif                         /* 0 */

/*
 * Find the useable ciphers|digests from dev/crypto - this is the first
 * thing called by the engine init crud which determines what it
 * can use for ciphers from this engine. We want to return
 * only what we can do, anythine else is handled by software.
 *
 * If we can't initialize the device to do anything useful for
 * any reason, we want to return a NULL array, and 0 length,
 * which forces everything to be done is software. By putting
 * the initalization of the device in here, we ensure we can
 * use this engine as the default, and if for whatever reason
 * /dev/crypto won't do what we want it will just be done in
 * software
 *
 * This can (should) be greatly expanded to perhaps take into
 * account speed of the device, and what we want to do.
 * (although the disabling of particular alg's could be controlled
 * by the device driver with sysctl's.) - this is where we
 * want most of the decisions made about what we actually want
 * to use from /dev/crypto.
 */
static int cryptodev_usable_ciphers(const int **nids)
{
    int i, count;

    count = get_cryptodev_ciphers(nids);
    /* add ciphers specific to cryptodev if found in kernel */
    for (i = 0; i < count; i++) {
        switch (*(*nids + i)) {
        case NID_aes_128_cbc_hmac_sha1:
            EVP_add_cipher(&cryptodev_aes_128_cbc_hmac_sha1);
            break;
        case NID_aes_256_cbc_hmac_sha1:
            EVP_add_cipher(&cryptodev_aes_256_cbc_hmac_sha1);
            break;
        }
    }
    return count;
}

static int cryptodev_usable_digests(const int **nids)
{
# ifdef USE_CRYPTODEV_DIGESTS
    return (get_cryptodev_digests(nids));
# else
    /*
     * XXXX just disable all digests for now, because it sucks.
     * we need a better way to decide this - i.e. I may not
     * want digests on slow cards like hifn on fast machines,
     * but might want them on slow or loaded machines, etc.
     * will also want them when using crypto cards that don't
     * suck moose gonads - would be nice to be able to decide something
     * as reasonable default without having hackery that's card dependent.
     * of course, the default should probably be just do everything,
     * with perhaps a sysctl to turn algoritms off (or have them off
     * by default) on cards that generally suck like the hifn.
     */
    *nids = NULL;
    return (0);
# endif
}

static int
cryptodev_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                 const unsigned char *in, size_t inl)
{
    struct crypt_op cryp;
    struct dev_crypto_state *state = ctx->cipher_data;
    struct session_op *sess = &state->d_sess;
    const void *iiv;
    unsigned char save_iv[EVP_MAX_IV_LENGTH];

    if (state->d_fd < 0)
        return (0);
    if (!inl)
        return (1);
    if ((inl % ctx->cipher->block_size) != 0)
        return (0);

    memset(&cryp, 0, sizeof(cryp));

    cryp.ses = sess->ses;
    cryp.flags = 0;
    cryp.len = inl;
    cryp.src = (caddr_t) in;
    cryp.dst = (caddr_t) out;
    cryp.mac = 0;

    cryp.op = ctx->encrypt ? COP_ENCRYPT : COP_DECRYPT;

    if (ctx->cipher->iv_len) {
        cryp.iv = (caddr_t) ctx->iv;
        if (!ctx->encrypt) {
            iiv = in + inl - ctx->cipher->iv_len;
            memcpy(save_iv, iiv, ctx->cipher->iv_len);
        }
    } else
        cryp.iv = NULL;

    if (ioctl(state->d_fd, CIOCCRYPT, &cryp) == -1) {
        /*
         * XXX need better errror handling this can fail for a number of
         * different reasons.
         */
        return (0);
    }

    if (ctx->cipher->iv_len) {
        if (ctx->encrypt)
            iiv = out + inl - ctx->cipher->iv_len;
        else
            iiv = save_iv;
        memcpy(ctx->iv, iiv, ctx->cipher->iv_len);
    }
    return (1);
}

static int cryptodev_aead_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 const unsigned char *in, size_t len)
{
    struct crypt_auth_op cryp;
    struct dev_crypto_state *state = ctx->cipher_data;
    struct session_op *sess = &state->d_sess;
    const void *iiv;
    unsigned char save_iv[EVP_MAX_IV_LENGTH];

    if (state->d_fd < 0)
        return (0);
    if (!len)
        return (1);
    if ((len % ctx->cipher->block_size) != 0)
        return (0);

    memset(&cryp, 0, sizeof(cryp));

    /* TODO: make a seamless integration with cryptodev flags */
    switch (ctx->cipher->nid) {
    case NID_aes_128_cbc_hmac_sha1:
    case NID_aes_256_cbc_hmac_sha1:
        cryp.flags = COP_FLAG_AEAD_TLS_TYPE;
    }
    cryp.ses = sess->ses;
    cryp.len = state->len;
    cryp.src = (caddr_t) in;
    cryp.dst = (caddr_t) out;
    cryp.auth_src = state->aad;
    cryp.auth_len = state->aad_len;

    cryp.op = ctx->encrypt ? COP_ENCRYPT : COP_DECRYPT;

    if (ctx->cipher->iv_len) {
        cryp.iv = (caddr_t) ctx->iv;
        if (!ctx->encrypt) {
            iiv = in + len - ctx->cipher->iv_len;
            memcpy(save_iv, iiv, ctx->cipher->iv_len);
        }
    } else
        cryp.iv = NULL;

    if (ioctl(state->d_fd, CIOCAUTHCRYPT, &cryp) == -1) {
        /*
         * XXX need better errror handling this can fail for a number of
         * different reasons.
         */
        return (0);
    }

    if (ctx->cipher->iv_len) {
        if (ctx->encrypt)
            iiv = out + len - ctx->cipher->iv_len;
        else
            iiv = save_iv;
        memcpy(ctx->iv, iiv, ctx->cipher->iv_len);
    }
    return (1);
}

static int
cryptodev_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                   const unsigned char *iv, int enc)
{
    struct dev_crypto_state *state = ctx->cipher_data;
    struct session_op *sess = &state->d_sess;
    int cipher = -1, i;

    for (i = 0; ciphers[i].id; i++)
        if (ctx->cipher->nid == ciphers[i].nid &&
            ctx->cipher->iv_len <= ciphers[i].ivmax &&
            ctx->key_len == ciphers[i].keylen) {
            cipher = ciphers[i].id;
            break;
        }

    if (!ciphers[i].id) {
        state->d_fd = -1;
        return (0);
    }

    memset(sess, 0, sizeof(struct session_op));

    if ((state->d_fd = get_dev_crypto()) < 0)
        return (0);

    sess->key = (caddr_t) key;
    sess->keylen = ctx->key_len;
    sess->cipher = cipher;

    if (ioctl(state->d_fd, CIOCGSESSION, sess) == -1) {
        put_dev_crypto(state->d_fd);
        state->d_fd = -1;
        return (0);
    }
    return (1);
}

/*
 * Save the encryption key provided by upper layers. This function is called
 * by EVP_CipherInit_ex to initialize the algorithm's extra data. We can't do
 * much here because the mac key is not available. The next call should/will
 * be to cryptodev_cbc_hmac_sha1_ctrl with parameter
 * EVP_CTRL_AEAD_SET_MAC_KEY, to set the hmac key. There we call CIOCGSESSION
 * with both the crypto and hmac keys.
 */
static int cryptodev_init_aead_key(EVP_CIPHER_CTX *ctx,
                                   const unsigned char *key,
                                   const unsigned char *iv, int enc)
{
    struct dev_crypto_state *state = ctx->cipher_data;
    struct session_op *sess = &state->d_sess;
    int cipher = -1, i;

    for (i = 0; ciphers[i].id; i++)
        if (ctx->cipher->nid == ciphers[i].nid &&
            ctx->cipher->iv_len <= ciphers[i].ivmax &&
            ctx->key_len == ciphers[i].keylen) {
            cipher = ciphers[i].id;
            break;
        }

    if (!ciphers[i].id) {
        state->d_fd = -1;
        return (0);
    }

    memset(sess, 0, sizeof(struct session_op));

    sess->key = (caddr_t) key;
    sess->keylen = ctx->key_len;
    sess->cipher = cipher;

    /* for whatever reason, (1) means success */
    return (1);
}

/*
 * free anything we allocated earlier when initting a
 * session, and close the session.
 */
static int cryptodev_cleanup(EVP_CIPHER_CTX *ctx)
{
    int ret = 0;
    struct dev_crypto_state *state = ctx->cipher_data;
    struct session_op *sess = &state->d_sess;

    if (state->d_fd < 0)
        return (0);

    /*
     * XXX if this ioctl fails, someting's wrong. the invoker may have called
     * us with a bogus ctx, or we could have a device that for whatever
     * reason just doesn't want to play ball - it's not clear what's right
     * here - should this be an error? should it just increase a counter,
     * hmm. For right now, we return 0 - I don't believe that to be "right".
     * we could call the gorpy openssl lib error handlers that print messages
     * to users of the library. hmm..
     */

    if (ioctl(state->d_fd, CIOCFSESSION, &sess->ses) == -1) {
        ret = 0;
    } else {
        ret = 1;
    }
    put_dev_crypto(state->d_fd);
    state->d_fd = -1;

    return (ret);
}

static int cryptodev_cbc_hmac_sha1_ctrl(EVP_CIPHER_CTX *ctx, int type,
                                        int arg, void *ptr)
{
    switch (type) {
    case EVP_CTRL_AEAD_SET_MAC_KEY:
        {
            /* TODO: what happens with hmac keys larger than 64 bytes? */
            struct dev_crypto_state *state = ctx->cipher_data;
            struct session_op *sess = &state->d_sess;

            if ((state->d_fd = get_dev_crypto()) < 0)
                return (0);

            /* the rest should have been set in cryptodev_init_aead_key */
            sess->mackey = ptr;
            sess->mackeylen = arg;

            if (ioctl(state->d_fd, CIOCGSESSION, sess) == -1) {
                put_dev_crypto(state->d_fd);
                state->d_fd = -1;
                return (0);
            }
            return (1);
        }
    case EVP_CTRL_AEAD_TLS1_AAD:
        {
            /* ptr points to the associated data buffer of 13 bytes */
            struct dev_crypto_state *state = ctx->cipher_data;
            unsigned char *p = ptr;
            unsigned int cryptlen = p[arg - 2] << 8 | p[arg - 1];
            unsigned int maclen, padlen;
            unsigned int bs = ctx->cipher->block_size;

            state->aad = ptr;
            state->aad_len = arg;
            state->len = cryptlen;

            /* TODO: this should be an extension of EVP_CIPHER struct */
            switch (ctx->cipher->nid) {
            case NID_aes_128_cbc_hmac_sha1:
            case NID_aes_256_cbc_hmac_sha1:
                maclen = SHA_DIGEST_LENGTH;
            }

            /* space required for encryption (not only TLS padding) */
            padlen = maclen;
            if (ctx->encrypt) {
                cryptlen += maclen;
                padlen += bs - (cryptlen % bs);
            }
            return padlen;
        }
    default:
        return -1;
    }
}

/*
 * libcrypto EVP stuff - this is how we get wired to EVP so the engine
 * gets called when libcrypto requests a cipher NID.
 */

/* RC4 */
const EVP_CIPHER cryptodev_rc4 = {
    NID_rc4,
    1, 16, 0,
    EVP_CIPH_VARIABLE_LENGTH,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    NULL,
    NULL,
    NULL
};

/* DES CBC EVP */
const EVP_CIPHER cryptodev_des_cbc = {
    NID_des_cbc,
    8, 8, 8,
    EVP_CIPH_CBC_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

/* 3DES CBC EVP */
const EVP_CIPHER cryptodev_3des_cbc = {
    NID_des_ede3_cbc,
    8, 24, 8,
    EVP_CIPH_CBC_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_bf_cbc = {
    NID_bf_cbc,
    8, 16, 8,
    EVP_CIPH_CBC_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_cast_cbc = {
    NID_cast5_cbc,
    8, 16, 8,
    EVP_CIPH_CBC_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_aes_cbc = {
    NID_aes_128_cbc,
    16, 16, 16,
    EVP_CIPH_CBC_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_aes_192_cbc = {
    NID_aes_192_cbc,
    16, 24, 16,
    EVP_CIPH_CBC_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_aes_256_cbc = {
    NID_aes_256_cbc,
    16, 32, 16,
    EVP_CIPH_CBC_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_aes_128_cbc_hmac_sha1 = {
    NID_aes_128_cbc_hmac_sha1,
    16, 16, 16,
    EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_AEAD_CIPHER,
    cryptodev_init_aead_key,
    cryptodev_aead_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    cryptodev_cbc_hmac_sha1_ctrl,
    NULL
};

const EVP_CIPHER cryptodev_aes_256_cbc_hmac_sha1 = {
    NID_aes_256_cbc_hmac_sha1,
    16, 32, 16,
    EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_AEAD_CIPHER,
    cryptodev_init_aead_key,
    cryptodev_aead_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    cryptodev_cbc_hmac_sha1_ctrl,
    NULL
};

# ifdef CRYPTO_AES_CTR
const EVP_CIPHER cryptodev_aes_ctr = {
    NID_aes_128_ctr,
    16, 16, 14,
    EVP_CIPH_CTR_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_aes_ctr_192 = {
    NID_aes_192_ctr,
    16, 24, 14,
    EVP_CIPH_CTR_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};

const EVP_CIPHER cryptodev_aes_ctr_256 = {
    NID_aes_256_ctr,
    16, 32, 14,
    EVP_CIPH_CTR_MODE,
    cryptodev_init_key,
    cryptodev_cipher,
    cryptodev_cleanup,
    sizeof(struct dev_crypto_state),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL
};
# endif
/*
 * Registered by the ENGINE when used to find out how to deal with
 * a particular NID in the ENGINE. this says what we'll do at the
 * top level - note, that list is restricted by what we answer with
 */
static int
cryptodev_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                         const int **nids, int nid)
{
    if (!cipher)
        return (cryptodev_usable_ciphers(nids));

    switch (nid) {
    case NID_rc4:
        *cipher = &cryptodev_rc4;
        break;
    case NID_des_ede3_cbc:
        *cipher = &cryptodev_3des_cbc;
        break;
    case NID_des_cbc:
        *cipher = &cryptodev_des_cbc;
        break;
    case NID_bf_cbc:
        *cipher = &cryptodev_bf_cbc;
        break;
    case NID_cast5_cbc:
        *cipher = &cryptodev_cast_cbc;
        break;
    case NID_aes_128_cbc:
        *cipher = &cryptodev_aes_cbc;
        break;
    case NID_aes_192_cbc:
        *cipher = &cryptodev_aes_192_cbc;
        break;
    case NID_aes_256_cbc:
        *cipher = &cryptodev_aes_256_cbc;
        break;
# ifdef CRYPTO_AES_CTR
    case NID_aes_128_ctr:
        *cipher = &cryptodev_aes_ctr;
        break;
    case NID_aes_192_ctr:
        *cipher = &cryptodev_aes_ctr_192;
        break;
    case NID_aes_256_ctr:
        *cipher = &cryptodev_aes_ctr_256;
        break;
# endif
    case NID_aes_128_cbc_hmac_sha1:
        *cipher = &cryptodev_aes_128_cbc_hmac_sha1;
        break;
    case NID_aes_256_cbc_hmac_sha1:
        *cipher = &cryptodev_aes_256_cbc_hmac_sha1;
        break;
    default:
        *cipher = NULL;
        break;
    }
    return (*cipher != NULL);
}

# ifdef USE_CRYPTODEV_DIGESTS

/* convert digest type to cryptodev */
static int digest_nid_to_cryptodev(int nid)
{
    int i;

    for (i = 0; digests[i].id; i++)
        if (digests[i].nid == nid)
            return (digests[i].id);
    return (0);
}

static int digest_key_length(int nid)
{
    int i;

    for (i = 0; digests[i].id; i++)
        if (digests[i].nid == nid)
            return digests[i].keylen;
    return (0);
}

static int cryptodev_digest_init(EVP_MD_CTX *ctx)
{
    struct dev_crypto_state *state = ctx->md_data;
    struct session_op *sess = &state->d_sess;
    int digest;

    if ((digest = digest_nid_to_cryptodev(ctx->digest->type)) == NID_undef) {
        printf("cryptodev_digest_init: Can't get digest \n");
        return (0);
    }

    memset(state, 0, sizeof(struct dev_crypto_state));

    if ((state->d_fd = get_dev_crypto()) < 0) {
        printf("cryptodev_digest_init: Can't get Dev \n");
        return (0);
    }

    sess->mackey = state->dummy_mac_key;
    sess->mackeylen = digest_key_length(ctx->digest->type);
    sess->mac = digest;

    if (ioctl(state->d_fd, CIOCGSESSION, sess) < 0) {
        put_dev_crypto(state->d_fd);
        state->d_fd = -1;
        printf("cryptodev_digest_init: Open session failed\n");
        return (0);
    }

    return (1);
}

static int cryptodev_digest_update(EVP_MD_CTX *ctx, const void *data,
                                   size_t count)
{
    struct crypt_op cryp;
    struct dev_crypto_state *state = ctx->md_data;
    struct session_op *sess = &state->d_sess;

    if (!data || state->d_fd < 0) {
        printf("cryptodev_digest_update: illegal inputs \n");
        return (0);
    }

    if (!count) {
        return (0);
    }

    if (!(ctx->flags & EVP_MD_CTX_FLAG_ONESHOT)) {
        /* if application doesn't support one buffer */
        state->mac_data =
            OPENSSL_realloc(state->mac_data, state->mac_len + count);

        if (!state->mac_data) {
            printf("cryptodev_digest_update: realloc failed\n");
            return (0);
        }

        memcpy(state->mac_data + state->mac_len, data, count);
        state->mac_len += count;

        return (1);
    }

    memset(&cryp, 0, sizeof(cryp));

    cryp.ses = sess->ses;
    cryp.flags = 0;
    cryp.len = count;
    cryp.src = (caddr_t) data;
    cryp.dst = NULL;
    cryp.mac = (caddr_t) state->digest_res;
    if (ioctl(state->d_fd, CIOCCRYPT, &cryp) < 0) {
        printf("cryptodev_digest_update: digest failed\n");
        return (0);
    }
    return (1);
}

static int cryptodev_digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct crypt_op cryp;
    struct dev_crypto_state *state = ctx->md_data;
    struct session_op *sess = &state->d_sess;

    int ret = 1;

    if (!md || state->d_fd < 0) {
        printf("cryptodev_digest_final: illegal input\n");
        return (0);
    }

    if (!(ctx->flags & EVP_MD_CTX_FLAG_ONESHOT)) {
        /* if application doesn't support one buffer */
        memset(&cryp, 0, sizeof(cryp));
        cryp.ses = sess->ses;
        cryp.flags = 0;
        cryp.len = state->mac_len;
        cryp.src = state->mac_data;
        cryp.dst = NULL;
        cryp.mac = (caddr_t) md;
        if (ioctl(state->d_fd, CIOCCRYPT, &cryp) < 0) {
            printf("cryptodev_digest_final: digest failed\n");
            return (0);
        }

        return 1;
    }

    memcpy(md, state->digest_res, ctx->digest->md_size);

    return (ret);
}

static int cryptodev_digest_cleanup(EVP_MD_CTX *ctx)
{
    int ret = 1;
    struct dev_crypto_state *state = ctx->md_data;
    struct session_op *sess = &state->d_sess;

    if (state == NULL)
        return 0;

    if (state->d_fd < 0) {
        printf("cryptodev_digest_cleanup: illegal input\n");
        return (0);
    }

    if (state->mac_data) {
        OPENSSL_free(state->mac_data);
        state->mac_data = NULL;
        state->mac_len = 0;
    }

    if (ioctl(state->d_fd, CIOCFSESSION, &sess->ses) < 0) {
        printf("cryptodev_digest_cleanup: failed to close session\n");
        ret = 0;
    } else {
        ret = 1;
    }
    put_dev_crypto(state->d_fd);
    state->d_fd = -1;

    return (ret);
}

static int cryptodev_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    struct dev_crypto_state *fstate = from->md_data;
    struct dev_crypto_state *dstate = to->md_data;
    struct session_op *sess;
    int digest;

    if (dstate == NULL || fstate == NULL)
        return 1;

    memcpy(dstate, fstate, sizeof(struct dev_crypto_state));

    sess = &dstate->d_sess;

    digest = digest_nid_to_cryptodev(to->digest->type);

    sess->mackey = dstate->dummy_mac_key;
    sess->mackeylen = digest_key_length(to->digest->type);
    sess->mac = digest;

    dstate->d_fd = get_dev_crypto();

    if (ioctl(dstate->d_fd, CIOCGSESSION, sess) < 0) {
        put_dev_crypto(dstate->d_fd);
        dstate->d_fd = -1;
        printf("cryptodev_digest_init: Open session failed\n");
        return (0);
    }

    if (fstate->mac_len != 0) {
        if (fstate->mac_data != NULL) {
            dstate->mac_data = OPENSSL_malloc(fstate->mac_len);
            memcpy(dstate->mac_data, fstate->mac_data, fstate->mac_len);
            dstate->mac_len = fstate->mac_len;
        }
    }

    return 1;
}

const EVP_MD cryptodev_sha1 = {
    NID_sha1,
    NID_undef,
    SHA_DIGEST_LENGTH,
    EVP_MD_FLAG_ONESHOT,
    cryptodev_digest_init,
    cryptodev_digest_update,
    cryptodev_digest_final,
    cryptodev_digest_copy,
    cryptodev_digest_cleanup,
    EVP_PKEY_NULL_method,
    SHA_CBLOCK,
    sizeof(struct dev_crypto_state),
};

const EVP_MD cryptodev_md5 = {
    NID_md5,
    NID_undef,
    16 /* MD5_DIGEST_LENGTH */ ,
    EVP_MD_FLAG_ONESHOT,
    cryptodev_digest_init,
    cryptodev_digest_update,
    cryptodev_digest_final,
    cryptodev_digest_copy,
    cryptodev_digest_cleanup,
    EVP_PKEY_NULL_method,
    64 /* MD5_CBLOCK */ ,
    sizeof(struct dev_crypto_state),
};

# endif                         /* USE_CRYPTODEV_DIGESTS */

static int
cryptodev_engine_digests(ENGINE *e, const EVP_MD **digest,
                         const int **nids, int nid)
{
    if (!digest)
        return (cryptodev_usable_digests(nids));

    switch (nid) {
# ifdef USE_CRYPTODEV_DIGESTS
    case NID_md5:
        *digest = &cryptodev_md5;
        break;
    case NID_sha1:
        *digest = &cryptodev_sha1;
        break;
    default:
# endif                         /* USE_CRYPTODEV_DIGESTS */
        *digest = NULL;
        break;
    }
    return (*digest != NULL);
}

/*
 * Convert a BIGNUM to the representation that /dev/crypto needs.
 * Upon completion of use, the caller is responsible for freeing
 * crp->crp_p.
 */
static int bn2crparam(const BIGNUM *a, struct crparam *crp)
{
    ssize_t bytes, bits;
    u_char *b;

    crp->crp_p = NULL;
    crp->crp_nbits = 0;

    bits = BN_num_bits(a);
    bytes = (bits + 7) / 8;

    b = malloc(bytes);
    if (b == NULL)
        return (1);
    memset(b, 0, bytes);

    crp->crp_p = (caddr_t) b;
    crp->crp_nbits = bits;

    BN_bn2bin(a, crp->crp_p);
    return (0);
}

/* Convert a /dev/crypto parameter to a BIGNUM */
static int crparam2bn(struct crparam *crp, BIGNUM *a)
{
    int bytes;

    bytes = (crp->crp_nbits + 7) / 8;

    if (bytes == 0)
        return (-1);

    BN_bin2bn(crp->crp_p, bytes, a);

    return (0);
}

static void zapparams(struct crypt_kop *kop)
{
    int i;

    for (i = 0; i < kop->crk_iparams + kop->crk_oparams; i++) {
        if (kop->crk_param[i].crp_p)
            free(kop->crk_param[i].crp_p);
        kop->crk_param[i].crp_p = NULL;
        kop->crk_param[i].crp_nbits = 0;
    }
}

static int
cryptodev_asym(struct crypt_kop *kop, int rlen, BIGNUM *r, int slen,
               BIGNUM *s)
{
    int fd, ret = -1;

    if ((fd = get_asym_dev_crypto()) < 0)
        return (ret);

    if (r) {
        kop->crk_param[kop->crk_iparams].crp_p = calloc(rlen, sizeof(char));
        kop->crk_param[kop->crk_iparams].crp_nbits = rlen * 8;
        kop->crk_oparams++;
    }
    if (s) {
        kop->crk_param[kop->crk_iparams + 1].crp_p =
            calloc(slen, sizeof(char));
        kop->crk_param[kop->crk_iparams + 1].crp_nbits = slen * 8;
        kop->crk_oparams++;
    }

    if (ioctl(fd, CIOCKEY, kop) == 0) {
        if (r)
            crparam2bn(&kop->crk_param[kop->crk_iparams], r);
        if (s)
            crparam2bn(&kop->crk_param[kop->crk_iparams + 1], s);
        ret = 0;
    }

    return (ret);
}

/* Close an opened instance of cryptodev engine */
void cryptodev_close_instance(void *handle)
{
    int fd;

    if (handle) {
        fd = *(int *)handle;
        close(fd);
        free(handle);
    }
}

/* Create an instance of cryptodev for asynchronous interface */
void *cryptodev_init_instance(void)
{
    int *fd = malloc(sizeof(int));

    if (fd) {
        if ((*fd = open("/dev/crypto", O_RDWR, 0)) == -1) {
            free(fd);
            return NULL;
        }
    }
    return fd;
}

static int
cryptodev_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                     const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    struct crypt_kop kop;
    int ret = 1;

    /*
     * Currently, we know we can do mod exp iff we can do any asymmetric
     * operations at all.
     */
    if (cryptodev_asymfeat == 0) {
        ret = BN_mod_exp(r, a, p, m, ctx);
        return (ret);
    }

    kop.crk_op = CRK_MOD_EXP;
    kop.crk_oparams = 0;
    kop.crk_status = 0;

    /* inputs: a^p % m */
    if (bn2crparam(a, &kop.crk_param[0]))
        goto err;
    if (bn2crparam(p, &kop.crk_param[1]))
        goto err;
    if (bn2crparam(m, &kop.crk_param[2]))
        goto err;
    kop.crk_iparams = 3;

    if (cryptodev_asym(&kop, BN_num_bytes(m), r, 0, NULL)) {
        const RSA_METHOD *meth = RSA_PKCS1_SSLeay();
        printf("OCF asym process failed, Running in software\n");
        ret = meth->bn_mod_exp(r, a, p, m, ctx, in_mont);

    } else if (ECANCELED == kop.crk_status) {
        const RSA_METHOD *meth = RSA_PKCS1_SSLeay();
        printf("OCF hardware operation cancelled. Running in Software\n");
        ret = meth->bn_mod_exp(r, a, p, m, ctx, in_mont);
    }
    /* else cryptodev operation worked ok ==> ret = 1 */

 err:
    zapparams(&kop);
    return (ret);
}

static int
cryptodev_rsa_nocrt_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                            BN_CTX *ctx)
{
    int r;
    ctx = BN_CTX_new();
    r = cryptodev_bn_mod_exp(r0, I, rsa->d, rsa->n, ctx, NULL);
    BN_CTX_free(ctx);
    return (r);
}

static int
cryptodev_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    struct crypt_kop kop;
    int ret = 1, f_len, p_len, q_len;
    unsigned char *f = NULL, *p = NULL, *q = NULL, *dp = NULL, *dq =
        NULL, *c = NULL;

    if (!rsa->p || !rsa->q || !rsa->dmp1 || !rsa->dmq1 || !rsa->iqmp) {
        /* XXX 0 means failure?? */
        return (0);
    }

    kop.crk_oparams = 0;
    kop.crk_status = 0;
    kop.crk_op = CRK_MOD_EXP_CRT;
    f_len = BN_num_bytes(rsa->n);
    spcf_bn2bin_ex(I, &f, &f_len);
    spcf_bn2bin(rsa->p, &p, &p_len);
    spcf_bn2bin(rsa->q, &q, &q_len);
    spcf_bn2bin_ex(rsa->dmp1, &dp, &p_len);
    spcf_bn2bin_ex(rsa->iqmp, &c, &p_len);
    spcf_bn2bin_ex(rsa->dmq1, &dq, &q_len);
    /* inputs: rsa->p rsa->q I rsa->dmp1 rsa->dmq1 rsa->iqmp */
    kop.crk_param[0].crp_p = p;
    kop.crk_param[0].crp_nbits = p_len * 8;
    kop.crk_param[1].crp_p = q;
    kop.crk_param[1].crp_nbits = q_len * 8;
    kop.crk_param[2].crp_p = f;
    kop.crk_param[2].crp_nbits = f_len * 8;
    kop.crk_param[3].crp_p = dp;
    kop.crk_param[3].crp_nbits = p_len * 8;
    /* dq must of length q, rest all of length p */
    kop.crk_param[4].crp_p = dq;
    kop.crk_param[4].crp_nbits = q_len * 8;
    kop.crk_param[5].crp_p = c;
    kop.crk_param[5].crp_nbits = p_len * 8;
    kop.crk_iparams = 6;

    if (cryptodev_asym(&kop, BN_num_bytes(rsa->n), r0, 0, NULL)) {
        const RSA_METHOD *meth = RSA_PKCS1_SSLeay();
        printf("OCF asym process failed, running in Software\n");
        ret = (*meth->rsa_mod_exp) (r0, I, rsa, ctx);

    } else if (ECANCELED == kop.crk_status) {
        const RSA_METHOD *meth = RSA_PKCS1_SSLeay();
        printf("OCF hardware operation cancelled. Running in Software\n");
        ret = (*meth->rsa_mod_exp) (r0, I, rsa, ctx);
    }
    /* else cryptodev operation worked ok ==> ret = 1 */

 err:
    zapparams(&kop);
    return (ret);
}

static RSA_METHOD cryptodev_rsa = {
    "cryptodev RSA method",
    NULL,                       /* rsa_pub_enc */
    NULL,                       /* rsa_pub_dec */
    NULL,                       /* rsa_priv_enc */
    NULL,                       /* rsa_priv_dec */
    NULL,
    NULL,
    NULL,                       /* init */
    NULL,                       /* finish */
    0,                          /* flags */
    NULL,                       /* app_data */
    NULL,                       /* rsa_sign */
    NULL                        /* rsa_verify */
};

static DSA_SIG *cryptodev_dsa_do_sign(const unsigned char *dgst, int dlen,
                                      DSA *dsa)
{
    struct crypt_kop kop;
    BIGNUM *c = NULL, *d = NULL;
    DSA_SIG *dsaret = NULL;
    int q_len = 0, r_len = 0, g_len = 0;
    int priv_key_len = 0, ret;
    unsigned char *q = NULL, *r = NULL, *g = NULL, *priv_key = NULL, *f =
        NULL;

    memset(&kop, 0, sizeof kop);
    if ((c = BN_new()) == NULL) {
        DSAerr(DSA_F_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if ((d = BN_new()) == NULL) {
        BN_free(c);
        DSAerr(DSA_F_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (spcf_bn2bin(dsa->p, &q, &q_len)) {
        DSAerr(DSA_F_DSA_DO_SIGN, DSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        goto err;
    }

    /* Get order of the field of private keys into plain buffer */
    if (spcf_bn2bin(dsa->q, &r, &r_len)) {
        DSAerr(DSA_F_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* sanity test */
    if (dlen > r_len) {
        DSAerr(DSA_F_DSA_DO_SIGN, DSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        goto err;
    }

    g_len = q_len;
    /**
     * Get generator into a plain buffer. If length is less than
     * q_len then add leading padding bytes.
     */
    if (spcf_bn2bin_ex(dsa->g, &g, &g_len)) {
        DSAerr(DSA_F_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    priv_key_len = r_len;
    /**
     * Get private key into a plain buffer. If length is less than
     * r_len then add leading padding bytes.
     */
    if (spcf_bn2bin_ex(dsa->priv_key, &priv_key, &priv_key_len)) {
        DSAerr(DSA_F_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Allocate memory to store hash. */
    f = OPENSSL_malloc(r_len);
    if (!f) {
        DSAerr(DSA_F_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Add padding, since SEC expects hash to of size r_len */
    if (dlen < r_len)
        memset(f, 0, r_len - dlen);

    /* Skip leading bytes if dgst_len < r_len */
    memcpy(f + r_len - dlen, dgst, dlen);

    kop.crk_op = CRK_DSA_SIGN;

    /* inputs: dgst dsa->p dsa->q dsa->g dsa->priv_key */
    kop.crk_param[0].crp_p = (void *)f;
    kop.crk_param[0].crp_nbits = r_len * 8;
    kop.crk_param[1].crp_p = (void *)q;
    kop.crk_param[1].crp_nbits = q_len * 8;
    kop.crk_param[2].crp_p = (void *)r;
    kop.crk_param[2].crp_nbits = r_len * 8;
    kop.crk_param[3].crp_p = (void *)g;
    kop.crk_param[3].crp_nbits = g_len * 8;
    kop.crk_param[4].crp_p = (void *)priv_key;
    kop.crk_param[4].crp_nbits = priv_key_len * 8;
    kop.crk_iparams = 5;

    ret = cryptodev_asym(&kop, r_len, c, r_len, d);

    if (ret) {
        DSAerr(DSA_F_DSA_DO_SIGN, DSA_R_DECODE_ERROR);
        goto err;
    }

    dsaret = DSA_SIG_new();
    if (dsaret == NULL)
        goto err;
    dsaret->r = c;
    dsaret->s = d;

    zapparams(&kop);
    return (dsaret);
 err:
    {
        const DSA_METHOD *meth = DSA_OpenSSL();
        if (c)
            BN_free(c);
        if (d)
            BN_free(d);
        dsaret = (meth->dsa_do_sign) (dgst, dlen, dsa);
        return (dsaret);
    }
}

static int
cryptodev_dsa_verify(const unsigned char *dgst, int dlen,
                     DSA_SIG *sig, DSA *dsa)
{
    struct crypt_kop kop;
    int dsaret = 1, q_len = 0, r_len = 0, g_len = 0;
    int w_len = 0, c_len = 0, d_len = 0, ret = -1;
    unsigned char *q = NULL, *r = NULL, *w = NULL, *g = NULL;
    unsigned char *c = NULL, *d = NULL, *f = NULL;

    memset(&kop, 0, sizeof kop);
    kop.crk_op = CRK_DSA_VERIFY;

    if (spcf_bn2bin(dsa->p, &q, &q_len)) {
        DSAerr(DSA_F_DSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    /* Get Order of field of private keys */
    if (spcf_bn2bin(dsa->q, &r, &r_len)) {
        DSAerr(DSA_F_DSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    g_len = q_len;
        /**
         * Get generator into a plain buffer. If length is less than
         * q_len then add leading padding bytes.
         */
    if (spcf_bn2bin_ex(dsa->g, &g, &g_len)) {
        DSAerr(DSA_F_DSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    w_len = q_len;
        /**
         * Get public key into a plain buffer. If length is less than
         * q_len then add leading padding bytes.
         */
    if (spcf_bn2bin_ex(dsa->pub_key, &w, &w_len)) {
        DSAerr(DSA_F_DSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
        /**
         * Get the 1st part of signature into a flat buffer with
         * appropriate padding
         */
    c_len = r_len;

    if (spcf_bn2bin_ex(sig->r, &c, &c_len)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

        /**
         * Get the 2nd part of signature into a flat buffer with
         * appropriate padding
         */
    d_len = r_len;

    if (spcf_bn2bin_ex(sig->s, &d, &d_len)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Sanity test */
    if (dlen > r_len) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Allocate memory to store hash. */
    f = OPENSSL_malloc(r_len);
    if (!f) {
        DSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Add padding, since SEC expects hash to of size r_len */
    if (dlen < r_len)
        memset(f, 0, r_len - dlen);

    /* Skip leading bytes if dgst_len < r_len */
    memcpy(f + r_len - dlen, dgst, dlen);

    /* inputs: dgst dsa->p dsa->q dsa->g dsa->pub_key sig->r sig->s */
    kop.crk_param[0].crp_p = (void *)f;
    kop.crk_param[0].crp_nbits = r_len * 8;
    kop.crk_param[1].crp_p = q;
    kop.crk_param[1].crp_nbits = q_len * 8;
    kop.crk_param[2].crp_p = r;
    kop.crk_param[2].crp_nbits = r_len * 8;
    kop.crk_param[3].crp_p = g;
    kop.crk_param[3].crp_nbits = g_len * 8;
    kop.crk_param[4].crp_p = w;
    kop.crk_param[4].crp_nbits = w_len * 8;
    kop.crk_param[5].crp_p = c;
    kop.crk_param[5].crp_nbits = c_len * 8;
    kop.crk_param[6].crp_p = d;
    kop.crk_param[6].crp_nbits = d_len * 8;
    kop.crk_iparams = 7;

    if ((cryptodev_asym(&kop, 0, NULL, 0, NULL))) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, DSA_R_DECODE_ERROR);
        goto err;
    }

    /*
     * OCF success value is 0, if not zero, change dsaret to fail
     */
    if (0 != kop.crk_status) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, DSA_R_DECODE_ERROR);
        goto err;
    }

    zapparams(&kop);
    return (dsaret);
 err:
    {
        const DSA_METHOD *meth = DSA_OpenSSL();
        dsaret = (meth->dsa_do_verify) (dgst, dlen, sig, dsa);
        return dsaret;
    }
}

/* Cryptodev DSA Key Gen routine */
static int cryptodev_dsa_keygen(DSA *dsa)
{
    struct crypt_kop kop;
    int ret = 1, g_len;
    unsigned char *g = NULL;

    if (dsa->priv_key == NULL) {
        if ((dsa->priv_key = BN_new()) == NULL)
            goto sw_try;
    }

    if (dsa->pub_key == NULL) {
        if ((dsa->pub_key = BN_new()) == NULL)
            goto sw_try;
    }

    g_len = BN_num_bytes(dsa->p);
        /**
         * Get generator into a plain buffer. If length is less than
         * p_len then add leading padding bytes.
         */
    if (spcf_bn2bin_ex(dsa->g, &g, &g_len)) {
        DSAerr(DSA_F_DSA_GENERATE_KEY, ERR_R_MALLOC_FAILURE);
        goto sw_try;
    }

    memset(&kop, 0, sizeof kop);

    kop.crk_op = CRK_DSA_GENERATE_KEY;
    if (bn2crparam(dsa->p, &kop.crk_param[0]))
        goto sw_try;
    if (bn2crparam(dsa->q, &kop.crk_param[1]))
        goto sw_try;
    kop.crk_param[2].crp_p = g;
    kop.crk_param[2].crp_nbits = g_len * 8;
    kop.crk_iparams = 3;

    /* pub_key is or prime length while priv key is of length of order */
    if (cryptodev_asym(&kop, BN_num_bytes(dsa->p), dsa->pub_key,
                       BN_num_bytes(dsa->q), dsa->priv_key))
        goto sw_try;

    return ret;
 sw_try:
    {
        const DSA_METHOD *meth = DSA_OpenSSL();
        ret = (meth->dsa_keygen) (dsa);
    }
    return ret;
}

static DSA_METHOD cryptodev_dsa = {
    "cryptodev DSA method",
    NULL,
    NULL,                       /* dsa_sign_setup */
    NULL,
    NULL,                       /* dsa_mod_exp */
    NULL,
    NULL,                       /* init */
    NULL,                       /* finish */
    0,                          /* flags */
    NULL                        /* app_data */
};

static ECDSA_METHOD cryptodev_ecdsa = {
    "cryptodev ECDSA method",
    NULL,
    NULL,                       /* ecdsa_sign_setup */
    NULL,
    NULL,
    0,                          /* flags */
    NULL                        /* app_data */
};

typedef enum ec_curve_s {
    EC_PRIME,
    EC_BINARY
} ec_curve_t;

/* ENGINE handler for ECDSA Sign */
static ECDSA_SIG *cryptodev_ecdsa_do_sign(const unsigned char *dgst,
                                          int dgst_len, const BIGNUM *in_kinv,
                                          const BIGNUM *in_r, EC_KEY *eckey)
{
    BIGNUM *m = NULL, *p = NULL, *a = NULL;
    BIGNUM *b = NULL, *x = NULL, *y = NULL;
    BN_CTX *ctx = NULL;
    ECDSA_SIG *ret = NULL;
    ECDSA_DATA *ecdsa = NULL;
    unsigned char *q = NULL, *r = NULL, *ab = NULL, *g_xy = NULL;
    unsigned char *s = NULL, *c = NULL, *d = NULL, *f = NULL, *tmp_dgst =
        NULL;
    int i = 0, q_len = 0, priv_key_len = 0, r_len = 0;
    int g_len = 0, d_len = 0, ab_len = 0;
    const BIGNUM *order = NULL, *priv_key = NULL;
    const EC_GROUP *group = NULL;
    struct crypt_kop kop;
    ec_curve_t ec_crv = EC_PRIME;

    memset(&kop, 0, sizeof(kop));
    ecdsa = ecdsa_check(eckey);
    if (!ecdsa) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);

    if (!group || !priv_key) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if ((ctx = BN_CTX_new()) == NULL || (m = BN_new()) == NULL ||
        (a = BN_new()) == NULL || (b = BN_new()) == NULL ||
        (p = BN_new()) == NULL || (x = BN_new()) == NULL ||
        (y = BN_new()) == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    order = &group->order;
    if (!order || BN_is_zero(order)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ECDSA_R_MISSING_PARAMETERS);
        goto err;
    }

    i = BN_num_bits(order);
    /*
     * Need to truncate digest if it is too long: first truncate whole bytes
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;

    if (!BN_bin2bn(dgst, dgst_len, m)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }

    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }

    /* copy the truncated bits into plain buffer */
    if (spcf_bn2bin(m, &tmp_dgst, &dgst_len)) {
        fprintf(stderr, "%s:%d: OPENSSL_malloc failec\n", __FUNCTION__,
                __LINE__);
        goto err;
    }

    ret = ECDSA_SIG_new();
    if (!ret) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }

    /* check if this is prime or binary EC request */
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
        NID_X9_62_prime_field) {
        ec_crv = EC_PRIME;
        /* get the generator point pair */
        if (!EC_POINT_get_affine_coordinates_GFp
            (group, EC_GROUP_get0_generator(group), x, y, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
            goto err;
        }

        /* get the ECC curve parameters */
        if (!EC_GROUP_get_curve_GFp(group, p, a, b, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
            goto err;
        }
    } else if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
               NID_X9_62_characteristic_two_field) {
        ec_crv = EC_BINARY;
        /* get the ECC curve parameters */
        if (!EC_GROUP_get_curve_GF2m(group, p, a, b, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
            goto err;
        }

        /* get the generator point pair */
        if (!EC_POINT_get_affine_coordinates_GF2m(group,
                                                  EC_GROUP_get0_generator
                                                  (group), x, y, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
            goto err;
        }
    } else {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
        goto err;
    }

    if (spcf_bn2bin(order, &r, &r_len)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (spcf_bn2bin(p, &q, &q_len)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    priv_key_len = r_len;

        /**
         * If BN_num_bytes of priv_key returns less then r_len then
         * add padding bytes before the key
         */
    if (spcf_bn2bin_ex(priv_key, &s, &priv_key_len)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Generation of ECC curve parameters */
    ab_len = 2 * q_len;
    ab = eng_copy_curve_points(a, b, ab_len, q_len);
    if (!ab) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (ec_crv == EC_BINARY) {
        if (eng_ec_get_cparam
            (EC_GROUP_get_curve_name(group), ab + q_len, q_len)) {
            unsigned char *c_temp = NULL;
            int c_temp_len = q_len;
            if (eng_ec_compute_cparam(b, p, &c_temp, &c_temp_len))
                memcpy(ab + q_len, c_temp, q_len);
            else
                goto err;
        }
        kop.curve_type = ECC_BINARY;
    }

    /* Calculation of Generator point */
    g_len = 2 * q_len;
    g_xy = eng_copy_curve_points(x, y, g_len, q_len);
    if (!g_xy) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Memory allocation for first part of digital signature */
    c = malloc(r_len);
    if (!c) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    d_len = r_len;

    /* Memory allocation for second part of digital signature */
    d = malloc(d_len);
    if (!d) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* memory for message representative */
    f = malloc(r_len);
    if (!f) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Add padding, since SEC expects hash to of size r_len */
    memset(f, 0, r_len - dgst_len);

    /* Skip leading bytes if dgst_len < r_len */
    memcpy(f + r_len - dgst_len, tmp_dgst, dgst_len);

    dgst_len += r_len - dgst_len;
    kop.crk_op = CRK_DSA_SIGN;
    /* inputs: dgst dsa->p dsa->q dsa->g dsa->priv_key */
    kop.crk_param[0].crp_p = f;
    kop.crk_param[0].crp_nbits = dgst_len * 8;
    kop.crk_param[1].crp_p = q;
    kop.crk_param[1].crp_nbits = q_len * 8;
    kop.crk_param[2].crp_p = r;
    kop.crk_param[2].crp_nbits = r_len * 8;
    kop.crk_param[3].crp_p = g_xy;
    kop.crk_param[3].crp_nbits = g_len * 8;
    kop.crk_param[4].crp_p = s;
    kop.crk_param[4].crp_nbits = priv_key_len * 8;
    kop.crk_param[5].crp_p = ab;
    kop.crk_param[5].crp_nbits = ab_len * 8;
    kop.crk_iparams = 6;
    kop.crk_param[6].crp_p = c;
    kop.crk_param[6].crp_nbits = d_len * 8;
    kop.crk_param[7].crp_p = d;
    kop.crk_param[7].crp_nbits = d_len * 8;
    kop.crk_oparams = 2;

    if (cryptodev_asym(&kop, 0, NULL, 0, NULL) == 0) {
        /* Check if ret->r and s needs to allocated */
        crparam2bn(&kop.crk_param[6], ret->r);
        crparam2bn(&kop.crk_param[7], ret->s);
    } else {
        const ECDSA_METHOD *meth = ECDSA_OpenSSL();
        ret = (meth->ecdsa_do_sign) (dgst, dgst_len, in_kinv, in_r, eckey);
    }
    kop.crk_param[0].crp_p = NULL;
    zapparams(&kop);
 err:
    if (!ret) {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }
    return ret;
}

static int cryptodev_ecdsa_verify(const unsigned char *dgst, int dgst_len,
                                  ECDSA_SIG *sig, EC_KEY *eckey)
{
    BIGNUM *m = NULL, *p = NULL, *a = NULL, *b = NULL;
    BIGNUM *x = NULL, *y = NULL, *w_x = NULL, *w_y = NULL;
    BN_CTX *ctx = NULL;
    ECDSA_DATA *ecdsa = NULL;
    unsigned char *q = NULL, *r = NULL, *ab = NULL, *g_xy = NULL, *w_xy =
        NULL;
    unsigned char *c = NULL, *d = NULL, *f = NULL, *tmp_dgst = NULL;
    int i = 0, q_len = 0, pub_key_len = 0, r_len = 0, c_len = 0, g_len = 0;
    int d_len = 0, ab_len = 0, ret = -1;
    const EC_POINT *pub_key = NULL;
    const BIGNUM *order = NULL;
    const EC_GROUP *group = NULL;
    ec_curve_t ec_crv = EC_PRIME;
    struct crypt_kop kop;

    memset(&kop, 0, sizeof kop);
    ecdsa = ecdsa_check(eckey);
    if (!ecdsa) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    group = EC_KEY_get0_group(eckey);
    pub_key = EC_KEY_get0_public_key(eckey);

    if (!group || !pub_key) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    if ((ctx = BN_CTX_new()) == NULL || (m = BN_new()) == NULL ||
        (a = BN_new()) == NULL || (b = BN_new()) == NULL ||
        (p = BN_new()) == NULL || (x = BN_new()) == NULL ||
        (y = BN_new()) == NULL || (w_x = BN_new()) == NULL ||
        (w_y = BN_new()) == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    order = &group->order;
    if (!order || BN_is_zero(order)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ECDSA_R_MISSING_PARAMETERS);
        goto err;
    }

    i = BN_num_bits(order);
    /*
     * Need to truncate digest if it is too long: first truncate whole *
     * bytes
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;

    if (!BN_bin2bn(dgst, dgst_len, m)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }

    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }
    /* copy the truncated bits into plain buffer */
    if (spcf_bn2bin(m, &tmp_dgst, &dgst_len)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* check if this is prime or binary EC request */
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
        NID_X9_62_prime_field) {
        ec_crv = EC_PRIME;

        /* get the generator point pair */
        if (!EC_POINT_get_affine_coordinates_GFp(group,
                                                 EC_GROUP_get0_generator
                                                 (group), x, y, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
            goto err;
        }

        /* get the public key pair for prime curve */
        if (!EC_POINT_get_affine_coordinates_GFp(group,
                                                 pub_key, w_x, w_y, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
            goto err;
        }

        /* get the ECC curve parameters */
        if (!EC_GROUP_get_curve_GFp(group, p, a, b, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
            goto err;
        }
    } else if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
               NID_X9_62_characteristic_two_field) {
        ec_crv = EC_BINARY;
        /* get the ECC curve parameters */
        if (!EC_GROUP_get_curve_GF2m(group, p, a, b, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
            goto err;
        }

        /* get the generator point pair */
        if (!EC_POINT_get_affine_coordinates_GF2m(group,
                                                  EC_GROUP_get0_generator
                                                  (group), x, y, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
            goto err;
        }

        /* get the public key pair for binary curve */
        if (!EC_POINT_get_affine_coordinates_GF2m(group,
                                                  pub_key, w_x, w_y, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
            goto err;
        }
    } else {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
        goto err;
    }

    /* Get the order of the subgroup of private keys */
    if (spcf_bn2bin((BIGNUM *)order, &r, &r_len)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Get the irreducible polynomial that creates the field */
    if (spcf_bn2bin(p, &q, &q_len)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Get the public key into a flat buffer with appropriate padding */
    pub_key_len = 2 * q_len;

    w_xy = eng_copy_curve_points(w_x, w_y, pub_key_len, q_len);
    if (!w_xy) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Generation of ECC curve parameters */
    ab_len = 2 * q_len;

    ab = eng_copy_curve_points(a, b, ab_len, q_len);
    if (!ab) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (ec_crv == EC_BINARY) {
        /* copy b' i.e c(b), instead of only b */
        if (eng_ec_get_cparam
            (EC_GROUP_get_curve_name(group), ab + q_len, q_len)) {
            unsigned char *c_temp = NULL;
            int c_temp_len = q_len;
            if (eng_ec_compute_cparam(b, p, &c_temp, &c_temp_len))
                memcpy(ab + q_len, c_temp, q_len);
            else
                goto err;
        }
        kop.curve_type = ECC_BINARY;
    }

    /* Calculation of Generator point */
    g_len = 2 * q_len;

    g_xy = eng_copy_curve_points(x, y, g_len, q_len);
    if (!g_xy) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

        /**
         * Get the 1st part of signature into a flat buffer with
         * appropriate padding
         */
    if (BN_num_bytes(sig->r) < r_len)
        c_len = r_len;

    if (spcf_bn2bin_ex(sig->r, &c, &c_len)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

        /**
         * Get the 2nd part of signature into a flat buffer with
         * appropriate padding
         */
    if (BN_num_bytes(sig->s) < r_len)
        d_len = r_len;

    if (spcf_bn2bin_ex(sig->s, &d, &d_len)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* memory for message representative */
    f = malloc(r_len);
    if (!f) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Add padding, since SEC expects hash to of size r_len */
    memset(f, 0, r_len - dgst_len);

    /* Skip leading bytes if dgst_len < r_len */
    memcpy(f + r_len - dgst_len, tmp_dgst, dgst_len);
    dgst_len += r_len - dgst_len;
    kop.crk_op = CRK_DSA_VERIFY;
    /* inputs: dgst dsa->p dsa->q dsa->g dsa->priv_key */
    kop.crk_param[0].crp_p = f;
    kop.crk_param[0].crp_nbits = dgst_len * 8;
    kop.crk_param[1].crp_p = q;
    kop.crk_param[1].crp_nbits = q_len * 8;
    kop.crk_param[2].crp_p = r;
    kop.crk_param[2].crp_nbits = r_len * 8;
    kop.crk_param[3].crp_p = g_xy;
    kop.crk_param[3].crp_nbits = g_len * 8;
    kop.crk_param[4].crp_p = w_xy;
    kop.crk_param[4].crp_nbits = pub_key_len * 8;
    kop.crk_param[5].crp_p = ab;
    kop.crk_param[5].crp_nbits = ab_len * 8;
    kop.crk_param[6].crp_p = c;
    kop.crk_param[6].crp_nbits = d_len * 8;
    kop.crk_param[7].crp_p = d;
    kop.crk_param[7].crp_nbits = d_len * 8;
    kop.crk_iparams = 8;

    if (cryptodev_asym(&kop, 0, NULL, 0, NULL) == 0) {
        /*
         * OCF success value is 0, if not zero, change ret to fail
         */
        if (0 == kop.crk_status)
            ret = 1;
    } else {
        const ECDSA_METHOD *meth = ECDSA_OpenSSL();

        ret = (meth->ecdsa_do_verify) (dgst, dgst_len, sig, eckey);
    }
    kop.crk_param[0].crp_p = NULL;
    zapparams(&kop);

 err:
    return ret;
}

static int cryptodev_dh_keygen(DH *dh)
{
    struct crypt_kop kop;
    int ret = 1, g_len;
    unsigned char *g = NULL;

    if (dh->priv_key == NULL) {
        if ((dh->priv_key = BN_new()) == NULL)
            goto sw_try;
    }

    if (dh->pub_key == NULL) {
        if ((dh->pub_key = BN_new()) == NULL)
            goto sw_try;
    }

    g_len = BN_num_bytes(dh->p);
        /**
         * Get generator into a plain buffer. If length is less than
         * q_len then add leading padding bytes.
         */
    if (spcf_bn2bin_ex(dh->g, &g, &g_len)) {
        DSAerr(DH_F_DH_GENERATE_KEY, ERR_R_MALLOC_FAILURE);
        goto sw_try;
    }

    memset(&kop, 0, sizeof kop);
    kop.crk_op = CRK_DH_GENERATE_KEY;
    if (bn2crparam(dh->p, &kop.crk_param[0]))
        goto sw_try;
    if (bn2crparam(dh->q, &kop.crk_param[1]))
        goto sw_try;
    kop.crk_param[2].crp_p = g;
    kop.crk_param[2].crp_nbits = g_len * 8;
    kop.crk_iparams = 3;

    /* pub_key is or prime length while priv key is of length of order */
    if (cryptodev_asym(&kop, BN_num_bytes(dh->p), dh->pub_key,
                       BN_num_bytes(dh->q), dh->priv_key))
        goto sw_try;

    return ret;
 sw_try:
    {
        const DH_METHOD *meth = DH_OpenSSL();
        ret = (meth->generate_key) (dh);
    }
    return ret;
}

static int
cryptodev_dh_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
    struct crypt_kop kop;
    int dhret = 1;
    int fd, p_len;
    BIGNUM *temp = NULL;
    unsigned char *padded_pub_key = NULL, *p = NULL;

    if ((fd = get_asym_dev_crypto()) < 0)
        goto sw_try;

    memset(&kop, 0, sizeof kop);
    kop.crk_op = CRK_DH_COMPUTE_KEY;
    /* inputs: dh->priv_key pub_key dh->p key */
    spcf_bn2bin(dh->p, &p, &p_len);
    spcf_bn2bin_ex(pub_key, &padded_pub_key, &p_len);
    if (bn2crparam(dh->priv_key, &kop.crk_param[0]))
        goto sw_try;

    kop.crk_param[1].crp_p = padded_pub_key;
    kop.crk_param[1].crp_nbits = p_len * 8;
    kop.crk_param[2].crp_p = p;
    kop.crk_param[2].crp_nbits = p_len * 8;
    kop.crk_iparams = 3;
    kop.crk_param[3].crp_p = (void *)key;
    kop.crk_param[3].crp_nbits = p_len * 8;
    kop.crk_oparams = 1;
    dhret = p_len;

    if (ioctl(fd, CIOCKEY, &kop))
        goto sw_try;

    if ((temp = BN_new())) {
        if (!BN_bin2bn(key, p_len, temp)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto sw_try;
        }
        if (dhret > BN_num_bytes(temp))
            dhret = BN_bn2bin(temp, key);
        BN_free(temp);
    }

    kop.crk_param[3].crp_p = NULL;
    zapparams(&kop);
    return (dhret);
 sw_try:
    {
        const DH_METHOD *meth = DH_OpenSSL();

        dhret = (meth->compute_key) (key, pub_key, dh);
    }
    return (dhret);
}

int cryptodev_ecdh_compute_key(void *out, size_t outlen,
                               const EC_POINT *pub_key, EC_KEY *ecdh,
                               void *(*KDF) (const void *in, size_t inlen,
                                             void *out, size_t *outlen))
{
    ec_curve_t ec_crv = EC_PRIME;
    unsigned char *q = NULL, *w_xy = NULL, *ab = NULL, *s = NULL, *r = NULL;
    BIGNUM *w_x = NULL, *w_y = NULL;
    int q_len = 0, ab_len = 0, pub_key_len = 0, r_len = 0, priv_key_len = 0;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    BN_CTX *ctx;
    EC_POINT *tmp = NULL;
    BIGNUM *x = NULL, *y = NULL;
    const BIGNUM *priv_key;
    const EC_GROUP *group = NULL;
    int ret = -1;
    size_t buflen, len;
    struct crypt_kop kop;

    memset(&kop, 0, sizeof kop);

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    w_x = BN_CTX_get(ctx);
    w_y = BN_CTX_get(ctx);

    if (!x || !y || !p || !a || !b || !w_x || !w_y) {
        ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    priv_key = EC_KEY_get0_private_key(ecdh);
    if (priv_key == NULL) {
        ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ECDH_R_NO_PRIVATE_VALUE);
        goto err;
    }

    group = EC_KEY_get0_group(ecdh);
    if ((tmp = EC_POINT_new(group)) == NULL) {
        ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
        NID_X9_62_prime_field) {
        ec_crv = EC_PRIME;

        if (!EC_POINT_get_affine_coordinates_GFp(group,
                                                 EC_GROUP_get0_generator
                                                 (group), x, y, ctx)) {
            ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ECDH_R_POINT_ARITHMETIC_FAILURE);
            goto err;
        }

        /* get the ECC curve parameters */
        if (!EC_GROUP_get_curve_GFp(group, p, a, b, ctx)) {
            ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_BN_LIB);
            goto err;
        }

        /* get the public key pair for prime curve */
        if (!EC_POINT_get_affine_coordinates_GFp
            (group, pub_key, w_x, w_y, ctx)) {
            ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_BN_LIB);
            goto err;
        }
    } else {
        ec_crv = EC_BINARY;

        if (!EC_POINT_get_affine_coordinates_GF2m(group,
                                                  EC_GROUP_get0_generator
                                                  (group), x, y, ctx)) {
            ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ECDH_R_POINT_ARITHMETIC_FAILURE);
            goto err;
        }

        /* get the ECC curve parameters */
        if (!EC_GROUP_get_curve_GF2m(group, p, a, b, ctx)) {
            ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_BN_LIB);
            goto err;
        }

        /* get the public key pair for binary curve */
        if (!EC_POINT_get_affine_coordinates_GF2m(group,
                                                  pub_key, w_x, w_y, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
            goto err;
        }
    }

    /* irreducible polynomial that creates the field */
    if (spcf_bn2bin((BIGNUM *)&group->order, &r, &r_len)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Get the irreducible polynomial that creates the field */
    if (spcf_bn2bin(p, &q, &q_len)) {
        ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /* Get the public key into a flat buffer with appropriate padding */
    pub_key_len = 2 * q_len;
    w_xy = eng_copy_curve_points(w_x, w_y, pub_key_len, q_len);
    if (!w_xy) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Generation of ECC curve parameters */
    ab_len = 2 * q_len;
    ab = eng_copy_curve_points(a, b, ab_len, q_len);
    if (!ab) {
        ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (ec_crv == EC_BINARY) {
        /* copy b' i.e c(b), instead of only b */
        if (eng_ec_get_cparam
            (EC_GROUP_get_curve_name(group), ab + q_len, q_len)) {
            unsigned char *c_temp = NULL;
            int c_temp_len = q_len;
            if (eng_ec_compute_cparam(b, p, &c_temp, &c_temp_len))
                memcpy(ab + q_len, c_temp, q_len);
            else
                goto err;
        }
        kop.curve_type = ECC_BINARY;
    } else
        kop.curve_type = ECC_PRIME;

    priv_key_len = r_len;

    /*
     * If BN_num_bytes of priv_key returns less then r_len then
     * add padding bytes before the key
     */
    if (spcf_bn2bin_ex((BIGNUM *)priv_key, &s, &priv_key_len)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    buflen = (EC_GROUP_get_degree(group) + 7) / 8;
    len = BN_num_bytes(x);
    if (len > buflen || q_len < buflen) {
        ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    kop.crk_op = CRK_DH_COMPUTE_KEY;
    kop.crk_param[0].crp_p = (void *)s;
    kop.crk_param[0].crp_nbits = priv_key_len * 8;
    kop.crk_param[1].crp_p = (void *)w_xy;
    kop.crk_param[1].crp_nbits = pub_key_len * 8;
    kop.crk_param[2].crp_p = (void *)q;
    kop.crk_param[2].crp_nbits = q_len * 8;
    kop.crk_param[3].crp_p = (void *)ab;
    kop.crk_param[3].crp_nbits = ab_len * 8;
    kop.crk_iparams = 4;
    kop.crk_param[4].crp_p = (void *)out;
    kop.crk_param[4].crp_nbits = q_len * 8;
    kop.crk_oparams = 1;
    ret = q_len;
    if (cryptodev_asym(&kop, 0, NULL, 0, NULL)) {
        const ECDH_METHOD *meth = ECDH_OpenSSL();
        ret = (meth->compute_key) (out, outlen, pub_key, ecdh, KDF);
    } else
        ret = q_len;
 err:
    kop.crk_param[4].crp_p = NULL;
    zapparams(&kop);
    return ret;
}

static DH_METHOD cryptodev_dh = {
    "cryptodev DH method",
    NULL,                       /* cryptodev_dh_generate_key */
    NULL,
    NULL,
    NULL,
    NULL,
    0,                          /* flags */
    NULL                        /* app_data */
};

static ECDH_METHOD cryptodev_ecdh = {
    "cryptodev ECDH method",
    NULL,                       /* cryptodev_ecdh_compute_key */
    NULL,
    0,                          /* flags */
    NULL                        /* app_data */
};

/*
 * ctrl right now is just a wrapper that doesn't do much
 * but I expect we'll want some options soon.
 */
static int
cryptodev_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
# ifdef HAVE_SYSLOG_R
    struct syslog_data sd = SYSLOG_DATA_INIT;
# endif

    switch (cmd) {
    default:
# ifdef HAVE_SYSLOG_R
        syslog_r(LOG_ERR, &sd, "cryptodev_ctrl: unknown command %d", cmd);
# else
        syslog(LOG_ERR, "cryptodev_ctrl: unknown command %d", cmd);
# endif
        break;
    }
    return (1);
}

void ENGINE_load_cryptodev(void)
{
    ENGINE *engine = ENGINE_new();
    int fd;

    if (engine == NULL)
        return;
    if ((fd = get_dev_crypto()) < 0) {
        ENGINE_free(engine);
        return;
    }

    /*
     * find out what asymmetric crypto algorithms we support
     */
    if (ioctl(fd, CIOCASYMFEAT, &cryptodev_asymfeat) == -1) {
        put_dev_crypto(fd);
        ENGINE_free(engine);
        return;
    }
    put_dev_crypto(fd);

    if (!ENGINE_set_id(engine, "cryptodev") ||
        !ENGINE_set_name(engine, "BSD cryptodev engine") ||
        !ENGINE_set_ciphers(engine, cryptodev_engine_ciphers) ||
        !ENGINE_set_digests(engine, cryptodev_engine_digests) ||
        !ENGINE_set_ctrl_function(engine, cryptodev_ctrl) ||
        !ENGINE_set_cmd_defns(engine, cryptodev_defns)) {
        ENGINE_free(engine);
        return;
    }

    if (ENGINE_set_RSA(engine, &cryptodev_rsa)) {
        const RSA_METHOD *rsa_meth = RSA_PKCS1_SSLeay();

        cryptodev_rsa.bn_mod_exp = rsa_meth->bn_mod_exp;
        cryptodev_rsa.rsa_mod_exp = rsa_meth->rsa_mod_exp;
        cryptodev_rsa.rsa_pub_enc = rsa_meth->rsa_pub_enc;
        cryptodev_rsa.rsa_pub_dec = rsa_meth->rsa_pub_dec;
        cryptodev_rsa.rsa_priv_enc = rsa_meth->rsa_priv_enc;
        cryptodev_rsa.rsa_priv_dec = rsa_meth->rsa_priv_dec;
        if (cryptodev_asymfeat & CRF_MOD_EXP) {
            cryptodev_rsa.bn_mod_exp = cryptodev_bn_mod_exp;
            if (cryptodev_asymfeat & CRF_MOD_EXP_CRT)
                cryptodev_rsa.rsa_mod_exp = cryptodev_rsa_mod_exp;
            else
                cryptodev_rsa.rsa_mod_exp = cryptodev_rsa_nocrt_mod_exp;
        }
    }

    if (ENGINE_set_DSA(engine, &cryptodev_dsa)) {
        const DSA_METHOD *meth = DSA_OpenSSL();

        memcpy(&cryptodev_dsa, meth, sizeof(DSA_METHOD));
        if (cryptodev_asymfeat & CRF_DSA_SIGN)
            cryptodev_dsa.dsa_do_sign = cryptodev_dsa_do_sign;
        if (cryptodev_asymfeat & CRF_DSA_VERIFY)
            cryptodev_dsa.dsa_do_verify = cryptodev_dsa_verify;
        if (cryptodev_asymfeat & CRF_DSA_GENERATE_KEY)
            cryptodev_dsa.dsa_keygen = cryptodev_dsa_keygen;
    }

    if (ENGINE_set_DH(engine, &cryptodev_dh)) {
        const DH_METHOD *dh_meth = DH_OpenSSL();
        memcpy(&cryptodev_dh, dh_meth, sizeof(DH_METHOD));
        if (cryptodev_asymfeat & CRF_DH_COMPUTE_KEY) {
            cryptodev_dh.compute_key = cryptodev_dh_compute_key;
        }
        if (cryptodev_asymfeat & CRF_DH_GENERATE_KEY) {
            cryptodev_dh.generate_key = cryptodev_dh_keygen;
        }
    }

    if (ENGINE_set_ECDSA(engine, &cryptodev_ecdsa)) {
        const ECDSA_METHOD *meth = ECDSA_OpenSSL();
        memcpy(&cryptodev_ecdsa, meth, sizeof(ECDSA_METHOD));
        if (cryptodev_asymfeat & CRF_DSA_SIGN) {
            cryptodev_ecdsa.ecdsa_do_sign = cryptodev_ecdsa_do_sign;
        }
        if (cryptodev_asymfeat & CRF_DSA_VERIFY) {
            cryptodev_ecdsa.ecdsa_do_verify = cryptodev_ecdsa_verify;
        }
    }

    if (ENGINE_set_ECDH(engine, &cryptodev_ecdh)) {
        const ECDH_METHOD *ecdh_meth = ECDH_OpenSSL();
        memcpy(&cryptodev_ecdh, ecdh_meth, sizeof(ECDH_METHOD));
        if (cryptodev_asymfeat & CRF_DH_COMPUTE_KEY) {
            cryptodev_ecdh.compute_key = cryptodev_ecdh_compute_key;
        }
    }

    ENGINE_add(engine);
    ENGINE_free(engine);
    ERR_clear_error();
}

#endif                          /* HAVE_CRYPTODEV */
