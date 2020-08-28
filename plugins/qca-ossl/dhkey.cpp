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

#include "dhkey.h"
#include "utils.h"

namespace opensslQCAPlugin {

//----------------------------------------------------------------------------
// DHKey
//----------------------------------------------------------------------------
class DHKeyMaker : public QThread
{
    Q_OBJECT
public:
    DLGroup domain;
    DH *    result;

    DHKeyMaker(const DLGroup &_domain, QObject *parent = nullptr) :
        QThread(parent), domain(_domain), result(nullptr) { }

    ~DHKeyMaker() override
    {
        wait();
        if (result)
            DH_free(result);
    }

    void run() override
    {
        DH *    dh  = DH_new();
        BIGNUM *bnp = bi2bn(domain.p());
        BIGNUM *bng = bi2bn(domain.g());
        if (!DH_set0_pqg(dh, bnp, nullptr, bng) || !DH_generate_key(dh)) {
            DH_free(dh);
            return;
        }
        result = dh;
    }

    DH *takeResult()
    {
        DH *dh = result;
        result = nullptr;
        return dh;
    }
};

DHKey::DHKey(Provider *p) : DHContext(p)
{
    keymaker = nullptr;
    sec      = false;
}

DHKey::DHKey(const DHKey &from) : DHContext(from.provider()), evp(from.evp)
{
    keymaker = nullptr;
    sec      = from.sec;
}

DHKey::~DHKey() { delete keymaker; }

Provider::Context *DHKey::clone() const { return new DHKey(*this); }

bool DHKey::isNull() const { return (evp.pkey ? false : true); }

PKey::Type DHKey::type() const { return PKey::DH; }

bool DHKey::isPrivate() const { return sec; }

bool DHKey::canExport() const { return true; }

void DHKey::convertToPublic()
{
    if (!sec)
        return;

    DH *          orig = EVP_PKEY_get0_DH(evp.pkey);
    DH *          dh   = DH_new();
    const BIGNUM *bnp, *bng, *bnpub_key;
    DH_get0_pqg(orig, &bnp, nullptr, &bng);
    DH_get0_key(orig, &bnpub_key, nullptr);

    DH_set0_key(dh, BN_dup(bnpub_key), nullptr);
    DH_set0_pqg(dh, BN_dup(bnp), nullptr, BN_dup(bng));

    evp.reset();

    evp.pkey = EVP_PKEY_new();
    EVP_PKEY_assign_DH(evp.pkey, dh);
    sec = false;
}

int DHKey::bits() const { return EVP_PKEY_bits(evp.pkey); }

SymmetricKey DHKey::deriveKey(const PKeyBase &theirs)
{
    DH *          dh   = EVP_PKEY_get0_DH(evp.pkey);
    DH *          them = EVP_PKEY_get0_DH(static_cast<const DHKey *>(&theirs)->evp.pkey);
    const BIGNUM *bnpub_key;
    DH_get0_key(them, &bnpub_key, nullptr);

    SecureArray result(DH_size(dh));
    int         ret = DH_compute_key((unsigned char *)result.data(), bnpub_key, dh);
    if (ret <= 0)
        return SymmetricKey();
    result.resize(ret);
    return SymmetricKey(result);
}

void DHKey::createPrivate(const DLGroup &domain, bool block)
{
    evp.reset();

    keymaker    = new DHKeyMaker(domain, !block ? this : nullptr);
    wasBlocking = block;
    if (block) {
        keymaker->run();
        km_finished();
    } else {
        connect(keymaker, &DHKeyMaker::finished, this, &DHKey::km_finished);
        keymaker->start();
    }
}

void DHKey::createPrivate(const DLGroup &domain, const BigInteger &y, const BigInteger &x)
{
    evp.reset();

    DH *    dh         = DH_new();
    BIGNUM *bnp        = bi2bn(domain.p());
    BIGNUM *bng        = bi2bn(domain.g());
    BIGNUM *bnpub_key  = bi2bn(y);
    BIGNUM *bnpriv_key = bi2bn(x);

    if (!DH_set0_key(dh, bnpub_key, bnpriv_key) || !DH_set0_pqg(dh, bnp, nullptr, bng)) {
        DH_free(dh);
        return;
    }

    evp.pkey = EVP_PKEY_new();
    EVP_PKEY_assign_DH(evp.pkey, dh);
    sec = true;
}

void DHKey::createPublic(const DLGroup &domain, const BigInteger &y)
{
    evp.reset();

    DH *    dh        = DH_new();
    BIGNUM *bnp       = bi2bn(domain.p());
    BIGNUM *bng       = bi2bn(domain.g());
    BIGNUM *bnpub_key = bi2bn(y);

    if (!DH_set0_key(dh, bnpub_key, nullptr) || !DH_set0_pqg(dh, bnp, nullptr, bng)) {
        DH_free(dh);
        return;
    }

    evp.pkey = EVP_PKEY_new();
    EVP_PKEY_assign_DH(evp.pkey, dh);
    sec = false;
}

DLGroup DHKey::domain() const
{
    DH *          dh = EVP_PKEY_get0_DH(evp.pkey);
    const BIGNUM *bnp, *bng;
    DH_get0_pqg(dh, &bnp, nullptr, &bng);
    return DLGroup(bn2bi(bnp), bn2bi(bng));
}

BigInteger DHKey::y() const
{
    DH *          dh = EVP_PKEY_get0_DH(evp.pkey);
    const BIGNUM *bnpub_key;
    DH_get0_key(dh, &bnpub_key, nullptr);
    return bn2bi(bnpub_key);
}

BigInteger DHKey::x() const
{
    DH *          dh = EVP_PKEY_get0_DH(evp.pkey);
    const BIGNUM *bnpriv_key;
    DH_get0_key(dh, nullptr, &bnpriv_key);
    return bn2bi(bnpriv_key);
}

void DHKey::km_finished()
{
    DH *dh = keymaker->takeResult();
    if (wasBlocking)
        delete keymaker;
    else
        keymaker->deleteLater();
    keymaker = nullptr;

    if (dh) {
        evp.pkey = EVP_PKEY_new();
        EVP_PKEY_assign_DH(evp.pkey, dh);
        sec = true;
    }

    if (!wasBlocking)
        emit finished();
}

}

#include "dhkey.moc"
