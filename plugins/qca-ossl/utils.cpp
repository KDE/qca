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

#include "utils.h"

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#ifndef RSA_F_RSA_OSSL_PRIVATE_DECRYPT
#define RSA_F_RSA_OSSL_PRIVATE_DECRYPT RSA_F_RSA_EAY_PRIVATE_DECRYPT
#endif

namespace opensslQCAPlugin {

int passphrase_cb(char *buf, int size, int rwflag, void *u)
{
    Q_UNUSED(buf);
    Q_UNUSED(size);
    Q_UNUSED(rwflag);
    Q_UNUSED(u);
    return 0;
}

//----------------------------------------------------------------------------
// QCA-based RSA_METHOD
//----------------------------------------------------------------------------

// only supports EMSA3_Raw for now
class QCA_RSA_METHOD
{
public:
    RSAPrivateKey key;

    QCA_RSA_METHOD(const RSAPrivateKey &_key, RSA *rsa)
    {
        key = _key;
        RSA_set_method(rsa, rsa_method());
        RSA_set_app_data(rsa, this);
        BIGNUM *bnn = bi2bn(_key.n());
        BIGNUM *bne = bi2bn(_key.e());

        RSA_set0_key(rsa, bnn, bne, nullptr);
    }

    RSA_METHOD *rsa_method()
    {
        static RSA_METHOD *ops = nullptr;

        if (!ops) {
            ops = RSA_meth_dup(RSA_get_default_method());
            RSA_meth_set_priv_enc(ops, nullptr);      // pkcs11_rsa_encrypt
            RSA_meth_set_priv_dec(ops, rsa_priv_dec); // pkcs11_rsa_encrypt
            RSA_meth_set_sign(ops, nullptr);
            RSA_meth_set_verify(ops, nullptr); // pkcs11_rsa_verify
            RSA_meth_set_finish(ops, rsa_finish);
        }
        return ops;
    }

    static int rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
    {
        QCA::EncryptionAlgorithm algo;

        if (padding == RSA_PKCS1_PADDING) {
            algo = QCA::EME_PKCS1v15;
        } else if (padding == RSA_PKCS1_OAEP_PADDING) {
            algo = QCA::EME_PKCS1_OAEP;
        } else {
            RSAerr(RSA_F_RSA_OSSL_PRIVATE_DECRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
            return -1;
        }

        QCA_RSA_METHOD *self = (QCA_RSA_METHOD *)RSA_get_app_data(rsa);

        QCA::SecureArray input;
        input.resize(flen);
        memcpy(input.data(), from, input.size());

        QCA::SecureArray output;

        if (self->key.decrypt(input, &output, algo)) {
            memcpy(to, output.data(), output.size());
            return output.size();
        }

        // XXX: An error should be set in this case too.
        return -1;
    }

    static int rsa_finish(RSA *rsa)
    {
        QCA_RSA_METHOD *self = (QCA_RSA_METHOD *)RSA_get_app_data(rsa);
        delete self;
        return 1;
    }
};

RSA *createFromExisting(const RSAPrivateKey &key)
{
    RSA *r = RSA_new();
    new QCA_RSA_METHOD(key, r); // will delete itself on RSA_free
    return r;
}

Validity convert_verify_error(int err)
{
    // TODO: ErrorExpiredCA
    Validity rc;
    switch (err) {
    case X509_V_ERR_CERT_REJECTED:
        rc = ErrorRejected;
        break;
    case X509_V_ERR_CERT_UNTRUSTED:
        rc = ErrorUntrusted;
        break;
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    case X509_V_ERR_CRL_SIGNATURE_FAILURE:
    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
    case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
        rc = ErrorSignatureFailed;
        break;
    case X509_V_ERR_INVALID_CA:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        rc = ErrorInvalidCA;
        break;
    case X509_V_ERR_INVALID_PURPOSE: // note: not used by store verify
        rc = ErrorInvalidPurpose;
        break;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        rc = ErrorSelfSigned;
        break;
    case X509_V_ERR_CERT_REVOKED:
        rc = ErrorRevoked;
        break;
    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        rc = ErrorPathLengthExceeded;
        break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_CRL_NOT_YET_VALID:
    case X509_V_ERR_CRL_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
        rc = ErrorExpired;
        break;
#ifndef LIBRESSL_VERSION_NUMBER
    case X509_V_ERR_EE_KEY_TOO_SMALL:
    case X509_V_ERR_CA_KEY_TOO_SMALL:
    case X509_V_ERR_CA_MD_TOO_WEAK:
        rc = ErrorSecurityLevel;
        break;
#endif
    case X509_V_ERR_APPLICATION_VERIFICATION:
    case X509_V_ERR_OUT_OF_MEM:
    case X509_V_ERR_UNABLE_TO_GET_CRL:
    case X509_V_ERR_CERT_CHAIN_TOO_LONG:
    default:
        rc = ErrorValidityUnknown;
        break;
    }
    return rc;
}

static void try_add_name_item(X509_NAME **name, int nid, const QString &val)
{
    if (val.isEmpty())
        return;
    const QByteArray buf = val.toLatin1();
    if (!(*name))
        *name = X509_NAME_new();
    X509_NAME_add_entry_by_NID(*name, nid, MBSTRING_ASC, (const unsigned char *)buf.data(), buf.size(), -1, 0);
}

X509_NAME *new_cert_name(const CertificateInfo &info)
{
    X509_NAME *name = nullptr;
    // FIXME support multiple items of each type
    try_add_name_item(&name, NID_commonName, info.value(CommonName));
    try_add_name_item(&name, NID_countryName, info.value(Country));
    try_add_name_item(&name, NID_localityName, info.value(Locality));
    try_add_name_item(&name, NID_stateOrProvinceName, info.value(State));
    try_add_name_item(&name, NID_organizationName, info.value(Organization));
    try_add_name_item(&name, NID_organizationalUnitName, info.value(OrganizationalUnit));
    return name;
}

QByteArray bio2ba(BIO *b)
{
    QByteArray buf;
    while (true) {
        QByteArray block(1024, 0);
        int        ret = BIO_read(b, block.data(), block.size());
        if (ret <= 0)
            break;
        block.resize(ret);
        buf.append(block);
        if (ret != 1024)
            break;
    }
    BIO_free(b);
    return buf;
}

BigInteger bn2bi(const BIGNUM *n)
{
    SecureArray buf(BN_num_bytes(n) + 1);
    buf[0] = 0; // positive
    BN_bn2bin(n, (unsigned char *)buf.data() + 1);
    return BigInteger(buf);
}

}
