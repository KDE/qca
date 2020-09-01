/*
 * Copyright (C) 2004-2007  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2004-2006  Brad Hards <bradh@frogmouth.net>
 * Copyright (C) 2013-2016  Ivan Romanov <drizt@land.ru>
 * Copyright (C) 2017       Fabian Vogt <fabian@ritter-vogt.de>
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

#include "rsakey.h"
#include "utils.h"

namespace opensslQCAPlugin {

//----------------------------------------------------------------------------
// RSAKey
//----------------------------------------------------------------------------
namespace {
    struct RsaDeleter
    {
        static inline void cleanup(void *pointer)
        {
            if (pointer)
                RSA_free((RSA *)pointer);
        }
    };

    struct BnDeleter
    {
        static inline void cleanup(void *pointer)
        {
            if (pointer)
                BN_free((BIGNUM *)pointer);
        }
    };
} // end of anonymous namespace

class RSAKeyMaker : public QThread
{
    Q_OBJECT
public:
    RSA *result;
    int  bits, exp;

    RSAKeyMaker(int _bits, int _exp, QObject *parent = nullptr) :
        QThread(parent), result(nullptr), bits(_bits), exp(_exp)
    {
    }

    ~RSAKeyMaker() override
    {
        wait();
        if (result)
            RSA_free(result);
    }

    void run() override
    {
        QScopedPointer<RSA, RsaDeleter> rsa(RSA_new());
        if (!rsa)
            return;

        QScopedPointer<BIGNUM, BnDeleter> e(BN_new());
        if (!e)
            return;

        BN_clear(e.data());
        if (BN_set_word(e.data(), exp) != 1)
            return;

        if (RSA_generate_key_ex(rsa.data(), bits, e.data(), nullptr) == 0)
            return;

        result = rsa.take();
    }

    RSA *takeResult()
    {
        RSA *rsa = result;
        result   = nullptr;
        return rsa;
    }
};

RSAKey::RSAKey(Provider *p) : RSAContext(p)
{
    keymaker = nullptr;
    sec      = false;
}

RSAKey::RSAKey(const RSAKey &from) : RSAContext(from.provider()), evp(from.evp)
{
    keymaker = nullptr;
    sec      = from.sec;
}

RSAKey::~RSAKey() { delete keymaker; }

Provider::Context *RSAKey::clone() const { return new RSAKey(*this); }

bool RSAKey::isNull() const { return (evp.pkey ? false : true); }

PKey::Type RSAKey::type() const { return PKey::RSA; }

bool RSAKey::isPrivate() const { return sec; }

bool RSAKey::canExport() const { return true; }

void RSAKey::convertToPublic()
{
    if (!sec)
        return;

    // extract the public key into DER format
    RSA *          rsa_pkey = EVP_PKEY_get0_RSA(evp.pkey);
    int            len      = i2d_RSAPublicKey(rsa_pkey, nullptr);
    SecureArray    result(len);
    unsigned char *p = (unsigned char *)result.data();
    i2d_RSAPublicKey(rsa_pkey, &p);
    p = (unsigned char *)result.data();

    // put the DER public key back into openssl
    evp.reset();
    RSA *rsa = d2i_RSAPublicKey(nullptr, (const unsigned char **)&p, result.size());
    evp.pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp.pkey, rsa);
    sec = false;
}

int RSAKey::bits() const { return EVP_PKEY_bits(evp.pkey); }

int RSAKey::maximumEncryptSize(EncryptionAlgorithm alg) const
{
    RSA *rsa  = EVP_PKEY_get0_RSA(evp.pkey);
    int  size = 0;
    switch (alg) {
    case EME_PKCS1v15:
        size = RSA_size(rsa) - 11 - 1;
        break;
    case EME_PKCS1_OAEP:
        size = RSA_size(rsa) - 41 - 1;
        break;
    case EME_PKCS1v15_SSL:
        size = RSA_size(rsa) - 11 - 1;
        break;
    case EME_NO_PADDING:
        size = RSA_size(rsa) - 1;
        break;
    }

    return size;
}

SecureArray RSAKey::encrypt(const SecureArray &in, EncryptionAlgorithm alg)
{
    RSA *       rsa = EVP_PKEY_get0_RSA(evp.pkey);
    SecureArray buf = in;
    int         max = maximumEncryptSize(alg);

    if (buf.size() > max)
        buf.resize(max);
    SecureArray result(RSA_size(rsa));

    int pad;
    switch (alg) {
    case EME_PKCS1v15:
        pad = RSA_PKCS1_PADDING;
        break;
    case EME_PKCS1_OAEP:
        pad = RSA_PKCS1_OAEP_PADDING;
        break;
    case EME_PKCS1v15_SSL:
        pad = RSA_SSLV23_PADDING;
        break;
    case EME_NO_PADDING:
        pad = RSA_NO_PADDING;
        break;
    default:
        return SecureArray();
        break;
    }

    int ret;
    if (isPrivate())
        ret = RSA_private_encrypt(buf.size(), (unsigned char *)buf.data(), (unsigned char *)result.data(), rsa, pad);
    else
        ret = RSA_public_encrypt(buf.size(), (unsigned char *)buf.data(), (unsigned char *)result.data(), rsa, pad);

    if (ret < 0)
        return SecureArray();
    result.resize(ret);

    return result;
}

bool RSAKey::decrypt(const SecureArray &in, SecureArray *out, EncryptionAlgorithm alg)
{
    RSA *       rsa = EVP_PKEY_get0_RSA(evp.pkey);
    SecureArray result(RSA_size(rsa));
    int         pad;

    switch (alg) {
    case EME_PKCS1v15:
        pad = RSA_PKCS1_PADDING;
        break;
    case EME_PKCS1_OAEP:
        pad = RSA_PKCS1_OAEP_PADDING;
        break;
    case EME_PKCS1v15_SSL:
        pad = RSA_SSLV23_PADDING;
        break;
    case EME_NO_PADDING:
        pad = RSA_NO_PADDING;
        break;
    default:
        return false;
        break;
    }

    int ret;
    if (isPrivate())
        ret = RSA_private_decrypt(in.size(), (unsigned char *)in.data(), (unsigned char *)result.data(), rsa, pad);
    else
        ret = RSA_public_decrypt(in.size(), (unsigned char *)in.data(), (unsigned char *)result.data(), rsa, pad);

    if (ret < 0)
        return false;
    result.resize(ret);

    *out = result;
    return true;
}

void RSAKey::startSign(SignatureAlgorithm alg, SignatureFormat)
{
    const EVP_MD *md = nullptr;
    if (alg == EMSA3_SHA1)
        md = EVP_sha1();
    else if (alg == EMSA3_MD5)
        md = EVP_md5();
#ifdef HAVE_OPENSSL_MD2
    else if (alg == EMSA3_MD2)
        md = EVP_md2();
#endif
    else if (alg == EMSA3_RIPEMD160)
        md = EVP_ripemd160();
    else if (alg == EMSA3_SHA224)
        md = EVP_sha224();
    else if (alg == EMSA3_SHA256)
        md = EVP_sha256();
    else if (alg == EMSA3_SHA384)
        md = EVP_sha384();
    else if (alg == EMSA3_SHA512)
        md = EVP_sha512();
#ifdef HAVE_OPENSSL_BLAKE2_512
    else if (alg == EMSA3_BLAKE2B512)
        md = EVP_blake2b512();
#endif
    else if (alg == EMSA3_Raw) {
        // md = 0
    }
    evp.startSign(md);
}

void RSAKey::startVerify(SignatureAlgorithm alg, SignatureFormat)
{
    const EVP_MD *md = nullptr;
    if (alg == EMSA3_SHA1)
        md = EVP_sha1();
    else if (alg == EMSA3_MD5)
        md = EVP_md5();
#ifdef HAVE_OPENSSL_MD2
    else if (alg == EMSA3_MD2)
        md = EVP_md2();
#endif
    else if (alg == EMSA3_RIPEMD160)
        md = EVP_ripemd160();
    else if (alg == EMSA3_SHA224)
        md = EVP_sha224();
    else if (alg == EMSA3_SHA256)
        md = EVP_sha256();
    else if (alg == EMSA3_SHA384)
        md = EVP_sha384();
    else if (alg == EMSA3_SHA512)
        md = EVP_sha512();
    else if (alg == EMSA3_Raw) {
        // md = 0
    }
    evp.startVerify(md);
}

void RSAKey::update(const MemoryRegion &in) { evp.update(in); }

QByteArray RSAKey::endSign() { return evp.endSign().toByteArray(); }

bool RSAKey::endVerify(const QByteArray &sig) { return evp.endVerify(sig); }

void RSAKey::createPrivate(int bits, int exp, bool block)
{
    evp.reset();

    keymaker    = new RSAKeyMaker(bits, exp, !block ? this : nullptr);
    wasBlocking = block;
    if (block) {
        keymaker->run();
        km_finished();
    } else {
        connect(keymaker, &RSAKeyMaker::finished, this, &RSAKey::km_finished);
        keymaker->start();
    }
}

void RSAKey::createPrivate(const BigInteger &n, const BigInteger &e, const BigInteger &p, const BigInteger &q,
                           const BigInteger &d)
{
    evp.reset();

    RSA *rsa = RSA_new();
    if (RSA_set0_key(rsa, bi2bn(n), bi2bn(e), bi2bn(d)) == 0 || RSA_set0_factors(rsa, bi2bn(p), bi2bn(q)) == 0) {
        // Free BIGNUMS?
        RSA_free(rsa);
        return;
    }

    // When private key has no Public Exponent (e) or Private Exponent (d)
    // need to disable blinding. Otherwise decryption will be broken.
    // http://www.mail-archive.com/openssl-users@openssl.org/msg63530.html
    if (e == BigInteger(0) || d == BigInteger(0))
        RSA_blinding_off(rsa);

    evp.pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp.pkey, rsa);
    sec = true;
}

void RSAKey::createPublic(const BigInteger &n, const BigInteger &e)
{
    evp.reset();

    RSA *rsa = RSA_new();
    if (RSA_set0_key(rsa, bi2bn(n), bi2bn(e), nullptr) == 0) {
        RSA_free(rsa);
        return;
    }

    evp.pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp.pkey, rsa);
    sec = false;
}

BigInteger RSAKey::n() const
{
    RSA *         rsa = EVP_PKEY_get0_RSA(evp.pkey);
    const BIGNUM *bnn;
    RSA_get0_key(rsa, &bnn, nullptr, nullptr);
    return bn2bi(bnn);
}

BigInteger RSAKey::e() const
{
    RSA *         rsa = EVP_PKEY_get0_RSA(evp.pkey);
    const BIGNUM *bne;
    RSA_get0_key(rsa, nullptr, &bne, nullptr);
    return bn2bi(bne);
}

BigInteger RSAKey::p() const
{
    RSA *         rsa = EVP_PKEY_get0_RSA(evp.pkey);
    const BIGNUM *bnp;
    RSA_get0_factors(rsa, &bnp, nullptr);
    return bn2bi(bnp);
}

BigInteger RSAKey::q() const
{
    RSA *         rsa = EVP_PKEY_get0_RSA(evp.pkey);
    const BIGNUM *bnq;
    RSA_get0_factors(rsa, nullptr, &bnq);
    return bn2bi(bnq);
}

BigInteger RSAKey::d() const
{
    RSA *         rsa = EVP_PKEY_get0_RSA(evp.pkey);
    const BIGNUM *bnd;
    RSA_get0_key(rsa, nullptr, nullptr, &bnd);
    return bn2bi(bnd);
}

void RSAKey::km_finished()
{
    RSA *rsa = keymaker->takeResult();
    if (wasBlocking)
        delete keymaker;
    else
        keymaker->deleteLater();
    keymaker = nullptr;

    if (rsa) {
        evp.pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(evp.pkey, rsa);
        sec = true;
    }

    if (!wasBlocking)
        emit finished();
}

}

#include "rsakey.moc"
