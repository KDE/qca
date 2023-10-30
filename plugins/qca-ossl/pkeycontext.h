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

#include "qcaprovider.h"

#include <openssl/ssl.h>

using namespace QCA;
namespace opensslQCAPlugin {

//----------------------------------------------------------------------------
// MyPKeyContext
//----------------------------------------------------------------------------
class MyPKeyContext : public PKeyContext
{
    Q_OBJECT
public:
    PKeyBase *k;

    MyPKeyContext(Provider *p);
    ~MyPKeyContext() override;

    Provider::Context *clone() const override;

    QList<PKey::Type>   supportedTypes() const override;
    QList<PKey::Type>   supportedIOTypes() const override;
    QList<PBEAlgorithm> supportedPBEAlgorithms() const override;

    PKeyBase       *key() override;
    const PKeyBase *key() const override;
    void            setKey(PKeyBase *key) override;
    bool            importKey(const PKeyBase *key) override;
    EVP_PKEY       *get_pkey() const;
    PKeyBase       *pkeyToBase(EVP_PKEY *pkey, bool sec) const;
    QByteArray      publicToDER() const override;
    QString         publicToPEM() const override;
    ConvertResult   publicFromDER(const QByteArray &in) override;
    ConvertResult   publicFromPEM(const QString &s) override;
    SecureArray     privateToDER(const SecureArray &passphrase, PBEAlgorithm pbe) const override;
    QString         privateToPEM(const SecureArray &passphrase, PBEAlgorithm pbe) const override;
    ConvertResult   privateFromDER(const SecureArray &in, const SecureArray &passphrase) override;
    ConvertResult   privateFromPEM(const QString &s, const SecureArray &passphrase) override;
};

}
