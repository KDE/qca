/*
 * Copyright (C) 2004  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2004-2006  Brad Hards <bradh@frogmouth.net>
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
#include <QtCrypto>

#include <QtCore/qplugin.h>

#include <QElapsedTimer>

#include <gcrypt.h>
#include <iostream>
#include <qstringlist.h>

namespace gcryptQCAPlugin {

#include "hkdf.c"
#include "pkcs5.c"

void check_error(const char *label, gcry_error_t err)
{
    // we ignore the case where it is not an error, and
    // we also don't flag weak keys.
    if ((GPG_ERR_NO_ERROR != err) && (GPG_ERR_WEAK_KEY != gpg_err_code(err))) {
        std::cout << "Failure (" << label << "): ";
        std::cout << gcry_strsource(err) << "/";
        std::cout << gcry_strerror(err) << std::endl;
    }
}

class gcryHashContext : public QCA::HashContext
{
    Q_OBJECT
public:
    gcryHashContext(int hashAlgorithm, QCA::Provider *p, const QString &type)
        : QCA::HashContext(p, type)
    {
        m_hashAlgorithm = hashAlgorithm;
        err             = gcry_md_open(&context, m_hashAlgorithm, 0);
        if (GPG_ERR_NO_ERROR != err) {
            std::cout << "Failure: ";
            std::cout << gcry_strsource(err) << "/";
            std::cout << gcry_strerror(err) << std::endl;
        }
    }

    ~gcryHashContext() override
    {
        gcry_md_close(context);
    }

    Context *clone() const override
    {
        return new gcryHashContext(m_hashAlgorithm, provider(), type());
    }

    void clear() override
    {
        gcry_md_reset(context);
    }

    void update(const QCA::MemoryRegion &a) override
    {
        gcry_md_write(context, a.data(), a.size());
    }

    QCA::MemoryRegion final() override
    {
        unsigned char *  md;
        QCA::SecureArray a(gcry_md_get_algo_dlen(m_hashAlgorithm));
        md = gcry_md_read(context, m_hashAlgorithm);
        memcpy(a.data(), md, a.size());
        return a;
    }

protected:
    gcry_md_hd_t context;
    gcry_error_t err;
    int          m_hashAlgorithm;
};

class gcryHMACContext : public QCA::MACContext
{
    Q_OBJECT
public:
    gcryHMACContext(int hashAlgorithm, QCA::Provider *p, const QString &type)
        : QCA::MACContext(p, type)
    {
        m_hashAlgorithm = hashAlgorithm;
        err             = gcry_md_open(&context, m_hashAlgorithm, GCRY_MD_FLAG_HMAC);
        if (GPG_ERR_NO_ERROR != err) {
            std::cout << "Failure: ";
            std::cout << gcry_strsource(err) << "/";
            std::cout << gcry_strerror(err) << std::endl;
        }
    }

    ~gcryHMACContext() override
    {
        gcry_md_close(context);
    }

    void setup(const QCA::SymmetricKey &key) override
    {
        gcry_md_setkey(context, key.data(), key.size());
    }

    Context *clone() const override
    {
        return new gcryHMACContext(m_hashAlgorithm, provider(), type());
    }

    void clear()
    {
        gcry_md_reset(context);
    }

    QCA::KeyLength keyLength() const override
    {
        return anyKeyLength();
    }

    void update(const QCA::MemoryRegion &a) override
    {
        gcry_md_write(context, a.data(), a.size());
    }

    void final(QCA::MemoryRegion *out) override
    {
        QCA::SecureArray sa(gcry_md_get_algo_dlen(m_hashAlgorithm), 0);
        unsigned char *  md;
        md = gcry_md_read(context, m_hashAlgorithm);
        memcpy(sa.data(), md, sa.size());
        *out = sa;
    }

protected:
    gcry_md_hd_t context;
    gcry_error_t err;
    int          m_hashAlgorithm;
};

class gcryCipherContext : public QCA::CipherContext
{
    Q_OBJECT
public:
    gcryCipherContext(int algorithm, int mode, bool pad, QCA::Provider *p, const QString &type)
        : QCA::CipherContext(p, type)
    {
        m_cryptoAlgorithm = algorithm;
        m_mode            = mode;
        m_pad             = pad;
    }

    void setup(QCA::Direction                   dir,
               const QCA::SymmetricKey &        key,
               const QCA::InitializationVector &iv,
               const QCA::AuthTag &             tag) override
    {
        Q_UNUSED(tag);
        m_direction = dir;
        err         = gcry_cipher_open(&context, m_cryptoAlgorithm, m_mode, 0);
        check_error("gcry_cipher_open", err);
        if ((GCRY_CIPHER_3DES == m_cryptoAlgorithm) && (key.size() == 16)) {
            // this is triple DES with two keys, and gcrypt wants three
            QCA::SymmetricKey keyCopy(key);
            QCA::SecureArray  thirdKey(key);
            thirdKey.resize(8);
            keyCopy += thirdKey;
            err = gcry_cipher_setkey(context, keyCopy.data(), keyCopy.size());
        } else {
            err = gcry_cipher_setkey(context, key.data(), key.size());
        }
        check_error("gcry_cipher_setkey", err);
        err = gcry_cipher_setiv(context, iv.data(), iv.size());
        check_error("gcry_cipher_setiv", err);
    }

    Context *clone() const override
    {
        return new gcryCipherContext(*this);
    }

    int blockSize() const override
    {
        size_t blockSize;
        gcry_cipher_algo_info(m_cryptoAlgorithm, GCRYCTL_GET_BLKLEN, nullptr, &blockSize);
        return blockSize;
    }

    QCA::AuthTag tag() const override
    {
        // For future implementation
        return QCA::AuthTag();
    }

    bool update(const QCA::SecureArray &in, QCA::SecureArray *out) override
    {
        QCA::SecureArray result(in.size());
        if (QCA::Encode == m_direction) {
            err = gcry_cipher_encrypt(
                context, (unsigned char *)result.data(), result.size(), (unsigned char *)in.data(), in.size());
        } else {
            err = gcry_cipher_decrypt(
                context, (unsigned char *)result.data(), result.size(), (unsigned char *)in.data(), in.size());
        }
        check_error("update cipher encrypt/decrypt", err);
        result.resize(in.size());
        *out = result;
        return true;
    }

    bool final(QCA::SecureArray *out) override
    {
        QCA::SecureArray result;
        if (m_pad) {
            result.resize(blockSize());
            if (QCA::Encode == m_direction) {
                err = gcry_cipher_encrypt(context, (unsigned char *)result.data(), result.size(), nullptr, 0);
            } else {
                err = gcry_cipher_decrypt(context, (unsigned char *)result.data(), result.size(), nullptr, 0);
            }
            check_error("final cipher encrypt/decrypt", err);
        } else {
            // just return null
        }
        *out = result;
        return true;
    }

    QCA::KeyLength keyLength() const override
    {
        switch (m_cryptoAlgorithm) {
        case GCRY_CIPHER_DES:
            return QCA::KeyLength(8, 8, 1);
        case GCRY_CIPHER_AES128:
            return QCA::KeyLength(16, 16, 1);
        case GCRY_CIPHER_AES192:
            return QCA::KeyLength(24, 24, 1);
        case GCRY_CIPHER_3DES:
            // we do two and three key versions
            return QCA::KeyLength(16, 24, 8);
        case GCRY_CIPHER_AES256:
            return QCA::KeyLength(32, 32, 1);
        case GCRY_CIPHER_BLOWFISH:
            // Don't know - TODO
            return QCA::KeyLength(1, 32, 1);
        default:
            return QCA::KeyLength(0, 1, 1);
        }
    }

protected:
    gcry_cipher_hd_t context;
    gcry_error_t     err;
    int              m_cryptoAlgorithm;
    QCA::Direction   m_direction;
    int              m_mode;
    bool             m_pad;
};

class pbkdf1Context : public QCA::KDFContext
{
    Q_OBJECT
public:
    pbkdf1Context(int algorithm, QCA::Provider *p, const QString &type)
        : QCA::KDFContext(p, type)
    {
        m_hashAlgorithm = algorithm;
        err             = gcry_md_open(&context, m_hashAlgorithm, 0);
        if (GPG_ERR_NO_ERROR != err) {
            std::cout << "Failure: ";
            std::cout << gcry_strsource(err) << "/";
            std::cout << gcry_strerror(err) << std::endl;
        }
    }

    ~pbkdf1Context() override
    {
        gcry_md_close(context);
    }

    Context *clone() const override
    {
        return new pbkdf1Context(m_hashAlgorithm, provider(), type());
    }

    QCA::SymmetricKey makeKey(const QCA::SecureArray &         secret,
                              const QCA::InitializationVector &salt,
                              unsigned int                     keyLength,
                              unsigned int                     iterationCount) override
    {
        /* from RFC2898:
           Steps:

           1. If dkLen > 16 for MD2 and MD5, or dkLen > 20 for SHA-1, output
           "derived key too long" and stop.
        */
        if (keyLength > gcry_md_get_algo_dlen(m_hashAlgorithm)) {
            std::cout << "derived key too long" << std::endl;
            return QCA::SymmetricKey();
        }

        /*
           2. Apply the underlying hash function Hash for c iterations to the
           concatenation of the password P and the salt S, then extract
           the first dkLen octets to produce a derived key DK:

           T_1 = Hash (P || S) ,
           T_2 = Hash (T_1) ,
           ...
           T_c = Hash (T_{c-1}) ,
           DK = Tc<0..dkLen-1>
        */
        // calculate T_1
        gcry_md_write(context, secret.data(), secret.size());
        gcry_md_write(context, salt.data(), salt.size());
        unsigned char *md;
        md = gcry_md_read(context, m_hashAlgorithm);
        QCA::SecureArray a(gcry_md_get_algo_dlen(m_hashAlgorithm));
        memcpy(a.data(), md, a.size());

        // calculate T_2 up to T_c
        for (unsigned int i = 2; i <= iterationCount; ++i) {
            gcry_md_reset(context);
            gcry_md_write(context, a.data(), a.size());
            md = gcry_md_read(context, m_hashAlgorithm);
            memcpy(a.data(), md, a.size());
        }

        // shrink a to become DK, of the required length
        a.resize(keyLength);

        /*
           3. Output the derived key DK.
        */
        return a;
    }

    QCA::SymmetricKey makeKey(const QCA::SecureArray &         secret,
                              const QCA::InitializationVector &salt,
                              unsigned int                     keyLength,
                              int                              msecInterval,
                              unsigned int *                   iterationCount) override
    {
        Q_ASSERT(iterationCount != nullptr);
        QElapsedTimer timer;

        /*
           from RFC2898:
           Steps:

           1. If dkLen > 16 for MD2 and MD5, or dkLen > 20 for SHA-1, output
           "derived key too long" and stop.
        */
        if (keyLength > gcry_md_get_algo_dlen(m_hashAlgorithm)) {
            std::cout << "derived key too long" << std::endl;
            return QCA::SymmetricKey();
        }

        /*
           2. Apply the underlying hash function Hash for M milliseconds
           to the concatenation of the password P and the salt S, incrementing c,
           then extract the first dkLen octets to produce a derived key DK:

           time from 0 to M
           T_1 = Hash (P || S) ,
           T_2 = Hash (T_1) ,
           ...
           T_c = Hash (T_{c-1}) ,
           when time = 0: stop,
           DK = Tc<0..dkLen-1>
        */
        // calculate T_1
        gcry_md_write(context, secret.data(), secret.size());
        gcry_md_write(context, salt.data(), salt.size());
        unsigned char *md;
        md = gcry_md_read(context, m_hashAlgorithm);
        QCA::SecureArray a(gcry_md_get_algo_dlen(m_hashAlgorithm));
        memcpy(a.data(), md, a.size());

        // calculate T_2 up to T_c
        *iterationCount = 2 - 1; // <- Have to remove 1, unless it computes one
        timer.start();           // ^  time more than the base function
                                 // ^  with the same iterationCount
        while (timer.elapsed() < msecInterval) {
            gcry_md_reset(context);
            gcry_md_write(context, a.data(), a.size());
            md = gcry_md_read(context, m_hashAlgorithm);
            memcpy(a.data(), md, a.size());
            ++(*iterationCount);
        }

        // shrink a to become DK, of the required length
        a.resize(keyLength);

        /*
           3. Output the derived key DK.
        */
        return a;
    }

protected:
    gcry_md_hd_t context;
    gcry_error_t err;
    int          m_hashAlgorithm;
};

class pbkdf2Context : public QCA::KDFContext
{
    Q_OBJECT
public:
    pbkdf2Context(int algorithm, QCA::Provider *p, const QString &type)
        : QCA::KDFContext(p, type)
    {
        m_algorithm = algorithm;
    }

    Context *clone() const override
    {
        return new pbkdf2Context(*this);
    }

    QCA::SymmetricKey makeKey(const QCA::SecureArray &         secret,
                              const QCA::InitializationVector &salt,
                              unsigned int                     keyLength,
                              unsigned int                     iterationCount) override
    {
        QCA::SymmetricKey result(keyLength);
        gcry_error_t      retval = gcry_pbkdf2(m_algorithm,
                                          secret.data(),
                                          secret.size(),
                                          salt.data(),
                                          salt.size(),
                                          iterationCount,
                                          keyLength,
                                          result.data());
        if (retval == GPG_ERR_NO_ERROR) {
            return result;
        } else {
            // std::cout << "got: " << retval << std::endl;
            return QCA::SymmetricKey();
        }
    }

    QCA::SymmetricKey makeKey(const QCA::SecureArray &         secret,
                              const QCA::InitializationVector &salt,
                              unsigned int                     keyLength,
                              int                              msecInterval,
                              unsigned int *                   iterationCount) override
    {
        Q_ASSERT(iterationCount != nullptr);
        QCA::SymmetricKey result(keyLength);
        QElapsedTimer     timer;

        *iterationCount = 0;
        timer.start();

        while (timer.elapsed() < msecInterval) {
            gcry_pbkdf2(
                m_algorithm, secret.data(), secret.size(), salt.data(), salt.size(), 1, keyLength, result.data());
            ++(*iterationCount);
        }

        return makeKey(secret, salt, keyLength, *iterationCount);
    }

protected:
    int m_algorithm;
};

class hkdfContext : public QCA::HKDFContext
{
    Q_OBJECT
public:
    hkdfContext(int algorithm, QCA::Provider *p, const QString &type)
        : QCA::HKDFContext(p, type)
    {
        m_algorithm = algorithm;
    }

    Context *clone() const override
    {
        return new hkdfContext(*this);
    }

    QCA::SymmetricKey makeKey(const QCA::SecureArray &         secret,
                              const QCA::InitializationVector &salt,
                              const QCA::InitializationVector &info,
                              unsigned int                     keyLength) override
    {
        QCA::SymmetricKey result(keyLength);
        gcry_error_t      retval = gcry_hkdf(m_algorithm,
                                        secret.data(),
                                        secret.size(),
                                        salt.data(),
                                        salt.size(),
                                        info.data(),
                                        info.size(),
                                        result.data(),
                                        result.size());
        if (retval == GPG_ERR_NO_ERROR) {
            return result;
        } else {
            return QCA::SymmetricKey();
        }
    }

protected:
    int m_algorithm;
};

}

extern "C" {

static void *qca_func_malloc(size_t n)
{
    return qca_secure_alloc(n);
}

static void *qca_func_secure_malloc(size_t n)
{
    return qca_secure_alloc(n);
}

static void *qca_func_realloc(void *oldBlock, size_t newBlockSize)
{
    return qca_secure_realloc(oldBlock, newBlockSize);
}

static void qca_func_free(void *mem)
{
    qca_secure_free(mem);
}

int qca_func_secure_check(const void *)
{
    return (int)QCA::haveSecureMemory();
}
} // extern "C"

class gcryptProvider : public QCA::Provider
{
public:
    void init() override
    {
        if (!gcry_control(GCRYCTL_ANY_INITIALIZATION_P)) { /* No other library has already initialized libgcrypt. */

            if (!gcry_check_version(GCRYPT_VERSION)) {
                std::cout << "libgcrypt is too old (need " << GCRYPT_VERSION;
                std::cout << ", have " << gcry_check_version(nullptr) << ")" << std::endl;
            }
            gcry_set_allocation_handler(
                qca_func_malloc, qca_func_secure_malloc, qca_func_secure_check, qca_func_realloc, qca_func_free);
            gcry_control(GCRYCTL_INITIALIZATION_FINISHED);
        }
    }

    int qcaVersion() const override
    {
        return QCA_VERSION;
    }

    QString name() const override
    {
        return QStringLiteral("qca-gcrypt");
    }

    QStringList features() const override
    {
        QStringList list;
        list += QStringLiteral("sha1");
        list += QStringLiteral("md4");
        list += QStringLiteral("md5");
        list += QStringLiteral("ripemd160");
#ifdef GCRY_MD_SHA224
        list += QStringLiteral("sha224");
#endif
        list += QStringLiteral("sha256");
        list += QStringLiteral("sha384");
        list += QStringLiteral("sha512");
        list += QStringLiteral("hmac(md5)");
        list += QStringLiteral("hmac(sha1)");
#ifdef GCRY_MD_SHA224
        list += QStringLiteral("hmac(sha224)");
#endif
        list += QStringLiteral("hmac(sha256)");
        if (!(nullptr == gcry_check_version("1.3.0"))) {
            // 1.2 and earlier have broken implementation
            list += QStringLiteral("hmac(sha384)");
            list += QStringLiteral("hmac(sha512)");
        }
        list += QStringLiteral("hmac(ripemd160)");
        list += QStringLiteral("aes128-ecb");
        list += QStringLiteral("aes128-cfb");
        list += QStringLiteral("aes128-cbc");
        list += QStringLiteral("aes192-ecb");
        list += QStringLiteral("aes192-cfb");
        list += QStringLiteral("aes192-cbc");
        list += QStringLiteral("aes256-ecb");
        list += QStringLiteral("aes256-cfb");
        list += QStringLiteral("aes256-cbc");
        list += QStringLiteral("blowfish-ecb");
        list += QStringLiteral("blowfish-cbc");
        list += QStringLiteral("blowfish-cfb");
        list += QStringLiteral("tripledes-ecb");
        // 	list += QStringLiteral("des-ecb");
        list += QStringLiteral("des-cbc");
        list += QStringLiteral("des-cfb");
        if (!(nullptr == gcry_check_version("1.3.0"))) {
            // 1.2 branch and earlier doesn't support OFB mode
            list += QStringLiteral("aes128-ofb");
            list += QStringLiteral("aes192-ofb");
            list += QStringLiteral("aes256-ofb");
            list += QStringLiteral("des-ofb");
            list += QStringLiteral("tripledes-ofb");
            list += QStringLiteral("blowfish-ofb");
        }
        list += QStringLiteral("pbkdf1(sha1)");
        list += QStringLiteral("pbkdf2(sha1)");
        list += QStringLiteral("hkdf(sha256)");
        return list;
    }

    Context *createContext(const QString &type) override
    {
        // std::cout << "type: " << qPrintable(type) << std::endl;
        if (type == QLatin1String("sha1"))
            return new gcryptQCAPlugin::gcryHashContext(GCRY_MD_SHA1, this, type);
        else if (type == QLatin1String("md4"))
            return new gcryptQCAPlugin::gcryHashContext(GCRY_MD_MD4, this, type);
        else if (type == QLatin1String("md5"))
            return new gcryptQCAPlugin::gcryHashContext(GCRY_MD_MD5, this, type);
        else if (type == QLatin1String("ripemd160"))
            return new gcryptQCAPlugin::gcryHashContext(GCRY_MD_RMD160, this, type);
#ifdef GCRY_MD_SHA224
        else if (type == QLatin1String("sha224"))
            return new gcryptQCAPlugin::gcryHashContext(GCRY_MD_SHA224, this, type);
#endif
        else if (type == QLatin1String("sha256"))
            return new gcryptQCAPlugin::gcryHashContext(GCRY_MD_SHA256, this, type);
        else if (type == QLatin1String("sha384"))
            return new gcryptQCAPlugin::gcryHashContext(GCRY_MD_SHA384, this, type);
        else if (type == QLatin1String("sha512"))
            return new gcryptQCAPlugin::gcryHashContext(GCRY_MD_SHA512, this, type);
        else if (type == QLatin1String("hmac(md5)"))
            return new gcryptQCAPlugin::gcryHMACContext(GCRY_MD_MD5, this, type);
        else if (type == QLatin1String("hmac(sha1)"))
            return new gcryptQCAPlugin::gcryHMACContext(GCRY_MD_SHA1, this, type);
#ifdef GCRY_MD_SHA224
        else if (type == QLatin1String("hmac(sha224)"))
            return new gcryptQCAPlugin::gcryHMACContext(GCRY_MD_SHA224, this, type);
#endif
        else if (type == QLatin1String("hmac(sha256)"))
            return new gcryptQCAPlugin::gcryHMACContext(GCRY_MD_SHA256, this, type);
        else if (type == QLatin1String("hmac(sha384)"))
            return new gcryptQCAPlugin::gcryHMACContext(GCRY_MD_SHA384, this, type);
        else if (type == QLatin1String("hmac(sha512)"))
            return new gcryptQCAPlugin::gcryHMACContext(GCRY_MD_SHA512, this, type);
        else if (type == QLatin1String("hmac(ripemd160)"))
            return new gcryptQCAPlugin::gcryHMACContext(GCRY_MD_RMD160, this, type);
        else if (type == QLatin1String("aes128-ecb"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, false, this, type);
        else if (type == QLatin1String("aes128-cfb"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CFB, false, this, type);
        else if (type == QLatin1String("aes128-ofb"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_OFB, false, this, type);
        else if (type == QLatin1String("aes128-cbc"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, false, this, type);
        else if (type == QLatin1String("aes192-ecb"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB, false, this, type);
        else if (type == QLatin1String("aes192-cfb"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CFB, false, this, type);
        else if (type == QLatin1String("aes192-ofb"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OFB, false, this, type);
        else if (type == QLatin1String("aes192-cbc"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC, false, this, type);
        else if (type == QLatin1String("aes256-ecb"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, false, this, type);
        else if (type == QLatin1String("aes256-cfb"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, false, this, type);
        else if (type == QLatin1String("aes256-ofb"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB, false, this, type);
        else if (type == QLatin1String("aes256-cbc"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, false, this, type);
        else if (type == QLatin1String("blowfish-ecb"))
            return new gcryptQCAPlugin::gcryCipherContext(
                GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB, false, this, type);
        else if (type == QLatin1String("blowfish-cbc"))
            return new gcryptQCAPlugin::gcryCipherContext(
                GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CBC, false, this, type);
        else if (type == QLatin1String("blowfish-cfb"))
            return new gcryptQCAPlugin::gcryCipherContext(
                GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CFB, false, this, type);
        else if (type == QLatin1String("blowfish-ofb"))
            return new gcryptQCAPlugin::gcryCipherContext(
                GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_OFB, false, this, type);
        else if (type == QLatin1String("tripledes-ecb"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_ECB, false, this, type);
        else if (type == QLatin1String("tripledes-ofb"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_OFB, false, this, type);
        else if (type == QLatin1String("des-ecb"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, false, this, type);
        else if (type == QLatin1String("des-cbc"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC, false, this, type);
        else if (type == QLatin1String("des-cfb"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CFB, false, this, type);
        else if (type == QLatin1String("des-ofb"))
            return new gcryptQCAPlugin::gcryCipherContext(GCRY_CIPHER_DES, GCRY_CIPHER_MODE_OFB, false, this, type);
        else if (type == QLatin1String("pbkdf1(sha1)"))
            return new gcryptQCAPlugin::pbkdf1Context(GCRY_MD_SHA1, this, type);
        else if (type == QLatin1String("pbkdf2(sha1)"))
            return new gcryptQCAPlugin::pbkdf2Context(GCRY_MD_SHA1, this, type);
        else if (type == QLatin1String("hkdf(sha256)"))
            return new gcryptQCAPlugin::hkdfContext(GCRY_MD_SHA256, this, type);
        else
            return nullptr;
    }
};

class gcryptPlugin : public QObject, public QCAPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
    Q_INTERFACES(QCAPlugin)
public:
    QCA::Provider *createProvider() override
    {
        return new gcryptProvider;
    }
};

#include "qca-gcrypt.moc"
