/*
 * Copyright (C) 2017 Gabriel Souza Franco <gabrielfrancosouza@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 */

#ifndef OSSL110COMPAT_H
#define OSSL110COMPAT_H

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define RSA_F_RSA_METH_DUP 161

static void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr)
        *pr = sig->r;
    if (ps)
        *ps = sig->s;
}

static int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (!sig) return 0;
    sig->r = r;
    sig->s = s;
    return 1;
}

static void DSA_get0_pqg(const DSA *dsa, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    if (p)
        *p = dsa->p;
    if (q)
        *q = dsa->q;
    if (g)
        *g = dsa->g;
}

static int DSA_set0_pqg(DSA *dsa, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    if (!dsa) return 0;
    dsa->p = p;
    dsa->q = q;
    dsa->g = g;
    return 1;
}

static void RSA_get0_key(const RSA *rsa, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n)
        *n = rsa->n;
    if (e)
        *e = rsa->e;
    if (d)
        *d = rsa->d;
}

static int RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    if (!rsa) return 0;
    rsa->n = n;
    rsa->e = e;
    rsa->d = d;
    return 1;
}

static void RSA_get0_factors(const RSA *rsa, const BIGNUM **p, const BIGNUM **q)
{
    if (p)
        *p = rsa->p;
    if (q)
        *q = rsa->q;
}

static int RSA_set0_factors(RSA *rsa, BIGNUM *p, BIGNUM *q)
{
    if (!rsa) return 0;
    rsa->p = p;
    rsa->q = q;
    return 1;
}

static void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    if (p)
        *p = dh->p;
    if (q)
        *q = dh->q;
    if (g)
        *g = dh->g;
}

static int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    if (!dh) return 0;
    dh->p = p;
    dh->q = q;
    dh->g = g;
    return 1;
}

static void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key)
        *pub_key = dh->pub_key;
    if (priv_key)
        *priv_key = dh->priv_key;
}

static int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
    if (!dh) return 0;
    dh->pub_key = pub_key;
    dh->priv_key = priv_key;
    return 1;
}

static void DSA_get0_key(const DSA *dsa, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key)
        *pub_key = dsa->pub_key;
    if (priv_key)
        *priv_key = dsa->priv_key;
}

static int DSA_set0_key(DSA *dsa, BIGNUM *pub_key, BIGNUM *priv_key)
{
    if (!dsa) return 0;
    dsa->pub_key = pub_key;
    dsa->priv_key = priv_key;
    return 1;
}

static void X509_SIG_getm(const X509_SIG *sig, X509_ALGOR **palg, ASN1_OCTET_STRING **pdigest)
{
    if (palg)
        *palg = sig->algor;
    if (pdigest)
        *pdigest = sig->digest;
}

static void X509_REQ_get0_signature(const X509_REQ *req, const ASN1_BIT_STRING **psig, const X509_ALGOR **palg)
{
    if (psig)
        *psig = req->signature;
    if (palg)
        *palg = req->sig_alg;
}

static void X509_CRL_get0_signature(const X509_CRL *crl, const ASN1_BIT_STRING **psig, const X509_ALGOR **palg)
{
    if (psig)
        *psig = crl->signature;
    if (palg)
        *palg = crl->sig_alg;
}

static RSA_METHOD *RSA_meth_dup(const RSA_METHOD *meth)
{
    if (!meth)
        return NULL;

    RSA_METHOD *_meth = (RSA_METHOD *) OPENSSL_malloc(sizeof(*_meth));

    if (!_meth)
    {
        RSAerr(RSA_F_RSA_METH_DUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    memcpy(_meth, meth, sizeof(*_meth));
    _meth->name = strdup(meth->name);
    if (!_meth->name) {
        OPENSSL_free(_meth);
        RSAerr(RSA_F_RSA_METH_DUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    return _meth;
}

static int RSA_meth_set_priv_enc(RSA_METHOD *rsa, int (*priv_enc) (int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding))
{
    if (!rsa) return 0;
    rsa->rsa_priv_enc = priv_enc;
    return 1;
}

static int RSA_meth_set_priv_dec(RSA_METHOD *rsa, int (*priv_dec) (int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding))
{
    if (!rsa) return 0;
    rsa->rsa_priv_dec = priv_dec;
    return 1;
}

static int RSA_meth_set_sign(RSA_METHOD *meth, int (*sign) (int type, const unsigned char *m,
    unsigned int m_length, unsigned char *sigret, unsigned int *siglen, const RSA *rsa))
{
    if (!meth) return 0;
    meth->rsa_sign = sign;
    return 1;
}

static int RSA_meth_set_verify(RSA_METHOD *meth, int (*verify) (int dtype, const unsigned char *m,
    unsigned int m_length, const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa))
{
    if (!meth) return 0;
    meth->rsa_verify = verify;
    return 1;
}

static int RSA_meth_set_finish(RSA_METHOD *meth, int (*finish) (RSA *rsa))
{
    if (!meth) return 0;
    meth->finish = finish;
    return 1;
}

static HMAC_CTX *HMAC_CTX_new()
{
    HMAC_CTX *ctx = (HMAC_CTX *) OPENSSL_malloc(sizeof(HMAC_CTX));
    if (ctx)
        HMAC_CTX_init(ctx);
    return ctx;
}

static void HMAC_CTX_free(HMAC_CTX *ctx)
{
    if (!ctx)
        return;
    HMAC_CTX_cleanup(ctx);
    EVP_MD_CTX_cleanup(&ctx->i_ctx);
    EVP_MD_CTX_cleanup(&ctx->o_ctx);
    EVP_MD_CTX_cleanup(&ctx->md_ctx);
    OPENSSL_free(ctx);
}

#define ASN1_STRING_get0_data(...) (const unsigned char*)ASN1_STRING_data(__VA_ARGS__)

#define EVP_MD_CTX_new(...) EVP_MD_CTX_create(__VA_ARGS__)
#define EVP_MD_CTX_free(...) EVP_MD_CTX_destroy(__VA_ARGS__)

#define EVP_PKEY_up_ref(pkey) CRYPTO_add(&(pkey)->references, 1, CRYPTO_LOCK_EVP_PKEY)
#define X509_up_ref(cert) CRYPTO_add(&(cert)->references, 1, CRYPTO_LOCK_X509)
#define X509_CRL_up_ref(crl) CRYPTO_add(&(crl)->references, 1, CRYPTO_LOCK_X509_CRL)

#define EVP_PKEY_id(pky) (pky)->type
#define EVP_PKEY_get0_DSA(pky) (pky)->pkey.dsa
#define EVP_PKEY_get0_RSA(pky) (pky)->pkey.rsa
#define EVP_PKEY_get0_DH(pky) (pky)->pkey.dh

#define X509_CRL_get0_lastUpdate X509_CRL_get_lastUpdate
#define X509_CRL_get0_nextUpdate X509_CRL_get_nextUpdate

#define X509_REQ_get_signature_nid(req) OBJ_obj2nid((req)->sig_alg->algorithm)
#define X509_CRL_get_signature_nid(crl) OBJ_obj2nid((crl)->sig_alg->algorithm)

#define X509_REVOKED_get0_serialNumber(rev) (rev)->serialNumber
#define X509_REVOKED_get0_revocationDate(rev) (rev)->revocationDate

#endif // OPENSSL_VERSION_NUMBER < 0x10100000L

#endif // OSSL110COMPAT_H
