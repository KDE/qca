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

#pragma once

#include "evpkey.h"
#include "qcaprovider.h"

#include <openssl/rsa.h>

using namespace QCA;
namespace opensslQCAPlugin {

class RSAKeyMaker;
class RSAKey : public RSAContext
{
    Q_OBJECT
public:
    EVPKey       evp;
    RSAKeyMaker *keymaker;
    bool         wasBlocking;
    bool         sec;

    RSAKey(Provider *p);
    RSAKey(const RSAKey &from);
    ~RSAKey() override;

    Provider::Context *clone() const override;
    bool               isNull() const override;
    PKey::Type         type() const override;
    bool               isPrivate() const override;
    bool               canExport() const override;
    void               convertToPublic() override;
    int                bits() const override;
    int                maximumEncryptSize(EncryptionAlgorithm alg) const override;
    SecureArray        encrypt(const SecureArray &in, EncryptionAlgorithm alg) override;
    bool               decrypt(const SecureArray &in, SecureArray *out, EncryptionAlgorithm alg) override;
    void               startSign(SignatureAlgorithm alg, SignatureFormat) override;
    void               startVerify(SignatureAlgorithm alg, SignatureFormat) override;
    void               update(const MemoryRegion &in) override;
    QByteArray         endSign() override;
    bool               endVerify(const QByteArray &sig) override;
    void               createPrivate(int bits, int exp, bool block) override;
    void               createPrivate(const BigInteger &n,
                                     const BigInteger &e,
                                     const BigInteger &p,
                                     const BigInteger &q,
                                     const BigInteger &d) override;
    void               createPublic(const BigInteger &n, const BigInteger &e) override;

    BigInteger n() const override;
    BigInteger e() const override;
    BigInteger p() const override;
    BigInteger q() const override;
    BigInteger d() const override;

private Q_SLOTS:
    void km_finished();
};

}
