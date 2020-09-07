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

#include "pkeycontext.h"

#include "dhkey.h"
#include "dsakey.h"
#include "rsakey.h"
#include "utils.h"

#include <openssl/err.h>
#include <openssl/pkcs12.h>

namespace opensslQCAPlugin {

EVP_PKEY *qca_d2i_PKCS8PrivateKey(const SecureArray &in, EVP_PKEY **x, pem_password_cb *cb, void *u)
{
    PKCS8_PRIV_KEY_INFO *p8inf;

    // first try unencrypted form
    BIO *bi = BIO_new(BIO_s_mem());
    BIO_write(bi, in.data(), in.size());
    p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(bi, nullptr);
    BIO_free(bi);
    if (!p8inf) {
        X509_SIG *p8;

        // now try encrypted form
        bi = BIO_new(BIO_s_mem());
        BIO_write(bi, in.data(), in.size());
        p8 = d2i_PKCS8_bio(bi, nullptr);
        BIO_free(bi);
        if (!p8)
            return nullptr;

        // get passphrase
        char psbuf[PEM_BUFSIZE];
        int  klen;
        if (cb)
            klen = cb(psbuf, PEM_BUFSIZE, 0, u);
        else
            klen = PEM_def_callback(psbuf, PEM_BUFSIZE, 0, u);
        if (klen <= 0) {
            PEMerr(PEM_F_D2I_PKCS8PRIVATEKEY_BIO, PEM_R_BAD_PASSWORD_READ);
            X509_SIG_free(p8);
            return nullptr;
        }

        // decrypt it
        p8inf = PKCS8_decrypt(p8, psbuf, klen);
        X509_SIG_free(p8);
        if (!p8inf)
            return nullptr;
    }

    EVP_PKEY *ret = EVP_PKCS82PKEY(p8inf);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    if (!ret)
        return nullptr;
    if (x) {
        if (*x)
            EVP_PKEY_free(*x);
        *x = ret;
    }
    return ret;
}

static SecureArray bio2buf(BIO *b)
{
    SecureArray buf;
    while (true) {
        SecureArray block(1024);
        int         ret = BIO_read(b, block.data(), block.size());
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

MyPKeyContext::MyPKeyContext(Provider *p)
    : PKeyContext(p)
{
    k = nullptr;
}

MyPKeyContext::~MyPKeyContext()
{
    delete k;
}

Provider::Context *MyPKeyContext::clone() const
{
    MyPKeyContext *c = new MyPKeyContext(*this);
    c->k             = (PKeyBase *)k->clone();
    return c;
}

QList<PKey::Type> MyPKeyContext::supportedTypes() const
{
    QList<PKey::Type> list;
    list += PKey::RSA;
    list += PKey::DSA;
    list += PKey::DH;
    return list;
}

QList<PKey::Type> MyPKeyContext::supportedIOTypes() const
{
    QList<PKey::Type> list;
    list += PKey::RSA;
    list += PKey::DSA;
    return list;
}

QList<PBEAlgorithm> MyPKeyContext::supportedPBEAlgorithms() const
{
    QList<PBEAlgorithm> list;
    list += PBES2_DES_SHA1;
    list += PBES2_TripleDES_SHA1;
    return list;
}

PKeyBase *MyPKeyContext::key()
{
    return k;
}

const PKeyBase *MyPKeyContext::key() const
{
    return k;
}

void MyPKeyContext::setKey(PKeyBase *key)
{
    k = key;
}

bool MyPKeyContext::importKey(const PKeyBase *key)
{
    Q_UNUSED(key);
    return false;
}

EVP_PKEY *MyPKeyContext::get_pkey() const
{
    PKey::Type t = k->type();
    if (t == PKey::RSA)
        return static_cast<RSAKey *>(k)->evp.pkey;
    else if (t == PKey::DSA)
        return static_cast<DSAKey *>(k)->evp.pkey;
    else
        return static_cast<DHKey *>(k)->evp.pkey;
}

PKeyBase *MyPKeyContext::pkeyToBase(EVP_PKEY *pkey, bool sec) const
{
    PKeyBase *nk        = nullptr;
    int       pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));
    if (pkey_type == EVP_PKEY_RSA) {
        RSAKey *c   = new RSAKey(provider());
        c->evp.pkey = pkey;
        c->sec      = sec;
        nk          = c;
    } else if (pkey_type == EVP_PKEY_DSA) {
        DSAKey *c   = new DSAKey(provider());
        c->evp.pkey = pkey;
        c->sec      = sec;
        nk          = c;
    } else if (pkey_type == EVP_PKEY_DH) {
        DHKey *c    = new DHKey(provider());
        c->evp.pkey = pkey;
        c->sec      = sec;
        nk          = c;
    } else {
        EVP_PKEY_free(pkey);
    }
    return nk;
}

QByteArray MyPKeyContext::publicToDER() const
{
    EVP_PKEY *pkey = get_pkey();

    int pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));

    // OpenSSL does not have DH import/export support
    if (pkey_type == EVP_PKEY_DH)
        return QByteArray();

    BIO *bo = BIO_new(BIO_s_mem());
    i2d_PUBKEY_bio(bo, pkey);
    const QByteArray buf = bio2ba(bo);
    return buf;
}

QString MyPKeyContext::publicToPEM() const
{
    EVP_PKEY *pkey = get_pkey();

    int pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));

    // OpenSSL does not have DH import/export support
    if (pkey_type == EVP_PKEY_DH)
        return QString();

    BIO *bo = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bo, pkey);
    const QByteArray buf = bio2ba(bo);
    return QString::fromLatin1(buf);
}

ConvertResult MyPKeyContext::publicFromDER(const QByteArray &in)
{
    delete k;
    k = nullptr;

    BIO *bi = BIO_new(BIO_s_mem());
    BIO_write(bi, in.data(), in.size());
    EVP_PKEY *pkey = d2i_PUBKEY_bio(bi, nullptr);
    BIO_free(bi);

    if (!pkey)
        return ErrorDecode;

    k = pkeyToBase(pkey, false);
    if (k)
        return ConvertGood;
    else
        return ErrorDecode;
}

ConvertResult MyPKeyContext::publicFromPEM(const QString &s)
{
    delete k;
    k = nullptr;

    const QByteArray in = s.toLatin1();
    BIO *            bi = BIO_new(BIO_s_mem());
    BIO_write(bi, in.data(), in.size());
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bi, nullptr, passphrase_cb, nullptr);
    BIO_free(bi);

    if (!pkey)
        return ErrorDecode;

    k = pkeyToBase(pkey, false);
    if (k)
        return ConvertGood;
    else
        return ErrorDecode;
}

SecureArray MyPKeyContext::privateToDER(const SecureArray &passphrase, PBEAlgorithm pbe) const
{
    // if(pbe == PBEDefault)
    //    pbe = PBES2_TripleDES_SHA1;

    const EVP_CIPHER *cipher = nullptr;
    if (pbe == PBES2_TripleDES_SHA1)
        cipher = EVP_des_ede3_cbc();
    else if (pbe == PBES2_DES_SHA1)
        cipher = EVP_des_cbc();

    if (!cipher)
        return SecureArray();

    EVP_PKEY *pkey      = get_pkey();
    int       pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));

    // OpenSSL does not have DH import/export support
    if (pkey_type == EVP_PKEY_DH)
        return SecureArray();

    BIO *bo = BIO_new(BIO_s_mem());
    if (!passphrase.isEmpty())
        i2d_PKCS8PrivateKey_bio(bo, pkey, cipher, nullptr, 0, nullptr, (void *)passphrase.data());
    else
        i2d_PKCS8PrivateKey_bio(bo, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    SecureArray buf = bio2buf(bo);
    return buf;
}

QString MyPKeyContext::privateToPEM(const SecureArray &passphrase, PBEAlgorithm pbe) const
{
    // if(pbe == PBEDefault)
    //    pbe = PBES2_TripleDES_SHA1;

    const EVP_CIPHER *cipher = nullptr;
    if (pbe == PBES2_TripleDES_SHA1)
        cipher = EVP_des_ede3_cbc();
    else if (pbe == PBES2_DES_SHA1)
        cipher = EVP_des_cbc();

    if (!cipher)
        return QString();

    EVP_PKEY *pkey      = get_pkey();
    int       pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));

    // OpenSSL does not have DH import/export support
    if (pkey_type == EVP_PKEY_DH)
        return QString();

    BIO *bo = BIO_new(BIO_s_mem());
    if (!passphrase.isEmpty())
        PEM_write_bio_PKCS8PrivateKey(bo, pkey, cipher, nullptr, 0, nullptr, (void *)passphrase.data());
    else
        PEM_write_bio_PKCS8PrivateKey(bo, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    SecureArray buf = bio2buf(bo);
    return QString::fromLatin1(buf.toByteArray());
}

ConvertResult MyPKeyContext::privateFromDER(const SecureArray &in, const SecureArray &passphrase)
{
    delete k;
    k = nullptr;

    EVP_PKEY *pkey;
    if (!passphrase.isEmpty())
        pkey = qca_d2i_PKCS8PrivateKey(in, nullptr, nullptr, (void *)passphrase.data());
    else
        pkey = qca_d2i_PKCS8PrivateKey(in, nullptr, passphrase_cb, nullptr);

    if (!pkey)
        return ErrorDecode;

    k = pkeyToBase(pkey, true);
    if (k)
        return ConvertGood;
    else
        return ErrorDecode;
}

ConvertResult MyPKeyContext::privateFromPEM(const QString &s, const SecureArray &passphrase)
{
    delete k;
    k = nullptr;

    const QByteArray in = s.toLatin1();
    BIO *            bi = BIO_new(BIO_s_mem());
    BIO_write(bi, in.data(), in.size());
    EVP_PKEY *pkey;
    if (!passphrase.isEmpty())
        pkey = PEM_read_bio_PrivateKey(bi, nullptr, nullptr, (void *)passphrase.data());
    else
        pkey = PEM_read_bio_PrivateKey(bi, nullptr, passphrase_cb, nullptr);
    BIO_free(bi);

    if (!pkey)
        return ErrorDecode;

    k = pkeyToBase(pkey, true);
    if (k)
        return ConvertGood;
    else
        return ErrorDecode;
}

}
