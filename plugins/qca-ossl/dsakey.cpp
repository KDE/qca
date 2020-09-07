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

#include "dsakey.h"
#include "utils.h"

namespace opensslQCAPlugin {

// take lowest bytes of BIGNUM to fit
// pad with high byte zeroes to fit
static SecureArray bn2fixedbuf(const BIGNUM *n, int size)
{
    SecureArray buf(BN_num_bytes(n));
    BN_bn2bin(n, (unsigned char *)buf.data());

    SecureArray out(size);
    memset(out.data(), 0, size);
    int len = qMin(size, buf.size());
    memcpy(out.data() + (size - len), buf.data(), len);
    return out;
}

static SecureArray dsasig_der_to_raw(const SecureArray &in)
{
    DSA_SIG *            sig = DSA_SIG_new();
    const unsigned char *inp = (const unsigned char *)in.data();
    d2i_DSA_SIG(&sig, &inp, in.size());

    const BIGNUM *bnr, *bns;
    DSA_SIG_get0(sig, &bnr, &bns);

    SecureArray part_r = bn2fixedbuf(bnr, 20);
    SecureArray part_s = bn2fixedbuf(bns, 20);
    SecureArray result;
    result.append(part_r);
    result.append(part_s);

    DSA_SIG_free(sig);
    return result;
}

static SecureArray dsasig_raw_to_der(const SecureArray &in)
{
    if (in.size() != 40)
        return SecureArray();

    DSA_SIG *   sig = DSA_SIG_new();
    SecureArray part_r(20);
    BIGNUM *    bnr;
    SecureArray part_s(20);
    BIGNUM *    bns;
    memcpy(part_r.data(), in.data(), 20);
    memcpy(part_s.data(), in.data() + 20, 20);
    bnr = BN_bin2bn((const unsigned char *)part_r.data(), part_r.size(), nullptr);
    bns = BN_bin2bn((const unsigned char *)part_s.data(), part_s.size(), nullptr);

    if (DSA_SIG_set0(sig, bnr, bns) == 0)
        return SecureArray();
    // Not documented what happens in the failure case, free bnr and bns?

    int            len = i2d_DSA_SIG(sig, nullptr);
    SecureArray    result(len);
    unsigned char *p = (unsigned char *)result.data();
    i2d_DSA_SIG(sig, &p);

    DSA_SIG_free(sig);
    return result;
}

//----------------------------------------------------------------------------
// DSAKey
//----------------------------------------------------------------------------
class DSAKeyMaker : public QThread
{
    Q_OBJECT
public:
    DLGroup domain;
    DSA *   result;

    DSAKeyMaker(const DLGroup &_domain, QObject *parent = nullptr)
        : QThread(parent)
        , domain(_domain)
        , result(nullptr)
    {
    }

    ~DSAKeyMaker() override
    {
        wait();
        if (result)
            DSA_free(result);
    }

    void run() override
    {
        DSA *   dsa = DSA_new();
        BIGNUM *pne = bi2bn(domain.p()), *qne = bi2bn(domain.q()), *gne = bi2bn(domain.g());

        if (!DSA_set0_pqg(dsa, pne, qne, gne) || !DSA_generate_key(dsa)) {
            DSA_free(dsa);
            return;
        }
        result = dsa;
    }

    DSA *takeResult()
    {
        DSA *dsa = result;
        result   = nullptr;
        return dsa;
    }
};

DSAKey::DSAKey(Provider *p)
    : DSAContext(p)
{
    keymaker = nullptr;
    sec      = false;
}

DSAKey::DSAKey(const DSAKey &from)
    : DSAContext(from.provider())
    , evp(from.evp)
{
    keymaker = nullptr;
    sec      = from.sec;
}

DSAKey::~DSAKey()
{
    delete keymaker;
}

Provider::Context *DSAKey::clone() const
{
    return new DSAKey(*this);
}

bool DSAKey::isNull() const
{
    return (evp.pkey ? false : true);
}

PKey::Type DSAKey::type() const
{
    return PKey::DSA;
}

bool DSAKey::isPrivate() const
{
    return sec;
}

bool DSAKey::canExport() const
{
    return true;
}

void DSAKey::convertToPublic()
{
    if (!sec)
        return;

    // extract the public key into DER format
    DSA *          dsa_pkey = EVP_PKEY_get0_DSA(evp.pkey);
    int            len      = i2d_DSAPublicKey(dsa_pkey, nullptr);
    SecureArray    result(len);
    unsigned char *p = (unsigned char *)result.data();
    i2d_DSAPublicKey(dsa_pkey, &p);
    p = (unsigned char *)result.data();

    // put the DER public key back into openssl
    evp.reset();
    DSA *dsa = d2i_DSAPublicKey(nullptr, (const unsigned char **)&p, result.size());
    evp.pkey = EVP_PKEY_new();
    EVP_PKEY_assign_DSA(evp.pkey, dsa);
    sec = false;
}

int DSAKey::bits() const
{
    return EVP_PKEY_bits(evp.pkey);
}

void DSAKey::startSign(SignatureAlgorithm, SignatureFormat format)
{
    // openssl native format is DER, so transform otherwise
    if (format != DERSequence)
        transformsig = true;
    else
        transformsig = false;

    evp.startSign(EVP_sha1());
}

void DSAKey::startVerify(SignatureAlgorithm, SignatureFormat format)
{
    // openssl native format is DER, so transform otherwise
    if (format != DERSequence)
        transformsig = true;
    else
        transformsig = false;

    evp.startVerify(EVP_sha1());
}

void DSAKey::update(const MemoryRegion &in)
{
    evp.update(in);
}

QByteArray DSAKey::endSign()
{
    SecureArray out = evp.endSign();
    if (transformsig)
        return dsasig_der_to_raw(out).toByteArray();
    else
        return out.toByteArray();
}

bool DSAKey::endVerify(const QByteArray &sig)
{
    SecureArray in;
    if (transformsig)
        in = dsasig_raw_to_der(sig);
    else
        in = sig;
    return evp.endVerify(in);
}

void DSAKey::createPrivate(const DLGroup &domain, bool block)
{
    evp.reset();

    keymaker    = new DSAKeyMaker(domain, !block ? this : nullptr);
    wasBlocking = block;
    if (block) {
        keymaker->run();
        km_finished();
    } else {
        connect(keymaker, &DSAKeyMaker::finished, this, &DSAKey::km_finished);
        keymaker->start();
    }
}

void DSAKey::createPrivate(const DLGroup &domain, const BigInteger &y, const BigInteger &x)
{
    evp.reset();

    DSA *   dsa        = DSA_new();
    BIGNUM *bnp        = bi2bn(domain.p());
    BIGNUM *bnq        = bi2bn(domain.q());
    BIGNUM *bng        = bi2bn(domain.g());
    BIGNUM *bnpub_key  = bi2bn(y);
    BIGNUM *bnpriv_key = bi2bn(x);

    if (!DSA_set0_pqg(dsa, bnp, bnq, bng) || !DSA_set0_key(dsa, bnpub_key, bnpriv_key)) {
        DSA_free(dsa);
        return;
    }

    evp.pkey = EVP_PKEY_new();
    EVP_PKEY_assign_DSA(evp.pkey, dsa);
    sec = true;
}

void DSAKey::createPublic(const DLGroup &domain, const BigInteger &y)
{
    evp.reset();

    DSA *   dsa       = DSA_new();
    BIGNUM *bnp       = bi2bn(domain.p());
    BIGNUM *bnq       = bi2bn(domain.q());
    BIGNUM *bng       = bi2bn(domain.g());
    BIGNUM *bnpub_key = bi2bn(y);

    if (!DSA_set0_pqg(dsa, bnp, bnq, bng) || !DSA_set0_key(dsa, bnpub_key, nullptr)) {
        DSA_free(dsa);
        return;
    }

    evp.pkey = EVP_PKEY_new();
    EVP_PKEY_assign_DSA(evp.pkey, dsa);
    sec = false;
}

DLGroup DSAKey::domain() const
{
    DSA *         dsa = EVP_PKEY_get0_DSA(evp.pkey);
    const BIGNUM *bnp, *bnq, *bng;
    DSA_get0_pqg(dsa, &bnp, &bnq, &bng);
    return DLGroup(bn2bi(bnp), bn2bi(bnq), bn2bi(bng));
}

BigInteger DSAKey::y() const
{
    DSA *         dsa = EVP_PKEY_get0_DSA(evp.pkey);
    const BIGNUM *bnpub_key;
    DSA_get0_key(dsa, &bnpub_key, nullptr);
    return bn2bi(bnpub_key);
}

BigInteger DSAKey::x() const
{
    DSA *         dsa = EVP_PKEY_get0_DSA(evp.pkey);
    const BIGNUM *bnpriv_key;
    DSA_get0_key(dsa, nullptr, &bnpriv_key);
    return bn2bi(bnpriv_key);
}

void DSAKey::km_finished()
{
    DSA *dsa = keymaker->takeResult();
    if (wasBlocking)
        delete keymaker;
    else
        keymaker->deleteLater();
    keymaker = nullptr;

    if (dsa) {
        evp.pkey = EVP_PKEY_new();
        EVP_PKEY_assign_DSA(evp.pkey, dsa);
        sec = true;
    }

    if (!wasBlocking)
        emit finished();
}

}

#include "dsakey.moc"
