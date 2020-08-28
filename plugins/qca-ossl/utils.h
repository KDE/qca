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

#include <openssl/asn1.h>
#include <openssl/x509v3.h>

using namespace QCA;
namespace opensslQCAPlugin {

int        passphrase_cb(char *buf, int size, int rwflag, void *u);
RSA *      createFromExisting(const RSAPrivateKey &key);
Validity   convert_verify_error(int err);
X509_NAME *new_cert_name(const CertificateInfo &info);
QByteArray bio2ba(BIO *b);

inline QByteArray qca_ASN1_STRING_toByteArray(ASN1_STRING *x)
{
    return QByteArray(reinterpret_cast<const char *>(ASN1_STRING_get0_data(x)), ASN1_STRING_length(x));
}

inline BIGNUM *bi2bn(const BigInteger &n)
{
    SecureArray buf = n.toArray();
    return BN_bin2bn((const unsigned char *)buf.data(), buf.size(), nullptr);
}

BigInteger        bn2bi(const BIGNUM *n);
inline BigInteger bn2bi_free(BIGNUM *n)
{
    BigInteger bi = bn2bi(n);
    BN_free(n);
    return bi;
}

}
