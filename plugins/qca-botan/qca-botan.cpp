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
#include <QElapsedTimer>
#include <QtCrypto>
#include <QtPlugin>

#include <qstringlist.h>

#include <botan/auto_rng.h>
#include <botan/block_cipher.h>
#include <botan/filters.h>
#include <botan/hash.h>
#include <botan/hkdf.h>
#include <botan/hmac.h>
#include <botan/pbkdf.h>
#include <botan/stream_cipher.h>
#include <botan/version.h>

#include <cstdlib>
#include <iostream>

//-----------------------------------------------------------
class botanRandomContext : public QCA::RandomContext
{
    Q_OBJECT
public:
    botanRandomContext(QCA::Provider *p)
        : RandomContext(p)
    {
    }

    Context *clone() const override
    {
        return new botanRandomContext(*this);
    }

    QCA::SecureArray nextBytes(int size) override
    {
        QCA::SecureArray      buf(size);
        Botan::AutoSeeded_RNG rng;
        rng.randomize(reinterpret_cast<Botan::byte *>(buf.data()), buf.size());
        return buf;
    }
};

static QString qcaHashToBotanHash(const QString &type)
{
    if (type == QLatin1String("md2"))
        return QStringLiteral("MD2");
    else if (type == QLatin1String("md4"))
        return QStringLiteral("MD4");
    else if (type == QLatin1String("md5"))
        return QStringLiteral("MD5");
    else if (type == QLatin1String("sha1"))
        return QStringLiteral("SHA-1");
    else if (type == QLatin1String("sha256"))
        return QStringLiteral("SHA-256");
    else if (type == QLatin1String("sha384"))
        return QStringLiteral("SHA-384");
    else if (type == QLatin1String("sha512"))
        return QStringLiteral("SHA-512");
    else if (type == QLatin1String("ripemd160"))
        return QStringLiteral("RIPEMD-160");

    return {};
}

//-----------------------------------------------------------
class BotanHashContext : public QCA::HashContext
{
    Q_OBJECT
public:
    BotanHashContext(QCA::Provider *p, const QString &type)
        : QCA::HashContext(p, type)
    {
        const QString hashName = qcaHashToBotanHash(type);
        m_hashObj              = Botan::HashFunction::create(hashName.toStdString()).release();
    }

    ~BotanHashContext() override
    {
        delete m_hashObj;
    }

    bool isOk() const
    {
        return m_hashObj;
    }

    Context *clone() const override
    {
        return new BotanHashContext(provider(), type());
    }

    void clear() override
    {
        m_hashObj->clear();
    }

    void update(const QCA::MemoryRegion &a) override
    {
        m_hashObj->update((const Botan::byte *)a.data(), a.size());
    }

    QCA::MemoryRegion final() override
    {
        QCA::SecureArray a(m_hashObj->output_length());
        m_hashObj->final((Botan::byte *)a.data());
        return a;
    }

private:
    Botan::HashFunction *m_hashObj;
};

static QString qcaHmacToBotanHmac(const QString &type)
{
    if (type == QLatin1String("hmac(md5)"))
        return QStringLiteral("MD5");
    else if (type == QLatin1String("hmac(sha1)"))
        return QStringLiteral("SHA-1");
    else if (type == QLatin1String("hmac(sha256)"))
        return QStringLiteral("SHA-256");
    else if (type == QLatin1String("hmac(sha384)"))
        return QStringLiteral("SHA-384");
    else if (type == QLatin1String("hmac(sha512)"))
        return QStringLiteral("SHA-512");
    else if (type == QLatin1String("hmac(ripemd160)"))
        return QStringLiteral("RIPEMD-160");

    return {};
}

//-----------------------------------------------------------
class BotanHMACContext : public QCA::MACContext
{
    Q_OBJECT
public:
    BotanHMACContext(QCA::Provider *p, const QString &type)
        : QCA::MACContext(p, type)
    {
        const QString hashName = qcaHmacToBotanHmac(type);
        m_hashObj = new Botan::HMAC(Botan::HashFunction::create_or_throw(hashName.toStdString()).release());
        if (nullptr == m_hashObj) {
            std::cout << "null context object" << std::endl;
        }
    }

    ~BotanHMACContext() override
    {
        delete m_hashObj;
    }

    void setup(const QCA::SymmetricKey &key) override
    {
        // this often gets called with an empty key, because that is the default
        // in the QCA MessageAuthenticationCode constructor. Botan doesn't like
        // that happening.
        if (key.size() > 0) {
            m_hashObj->set_key((const Botan::byte *)key.data(), key.size());
        }
    }

    Context *clone() const override
    {
        return new BotanHMACContext(provider(), type());
    }

    void clear()
    {
        m_hashObj->clear();
    }

    QCA::KeyLength keyLength() const override
    {
        return anyKeyLength();
    }

    void update(const QCA::MemoryRegion &a) override
    {
        m_hashObj->update((const Botan::byte *)a.data(), a.size());
    }

    void final(QCA::MemoryRegion *out) override
    {
        QCA::SecureArray sa(m_hashObj->output_length(), 0);
        m_hashObj->final((Botan::byte *)sa.data());
        *out = sa;
    }

protected:
    Botan::HMAC *m_hashObj;
};

static QString qcaPbkdfToBotanPbkdf(const QString &pbkdf)
{
    if (pbkdf == QLatin1String("pbkdf1(sha1)"))
        return QStringLiteral("PBKDF1(SHA-1)");
    else if (pbkdf == QLatin1String("pbkdf1(md2)"))
        return QStringLiteral("PBKDF1(MD2)");
    else if (pbkdf == QLatin1String("pbkdf2(sha1)"))
        return QStringLiteral("PBKDF2(SHA-1)");

    return {};
}

//-----------------------------------------------------------
class BotanPBKDFContext : public QCA::KDFContext
{
    Q_OBJECT
public:
    BotanPBKDFContext(QCA::Provider *p, const QString &type)
        : QCA::KDFContext(p, type)
    {
        try {
            const QString kdfName = qcaPbkdfToBotanPbkdf(type);
            m_s2k                 = Botan::get_s2k(kdfName.toStdString());
        } catch (Botan::Exception &e) {
            m_s2k = nullptr;
        }
    }

    ~BotanPBKDFContext() override
    {
        delete m_s2k;
    }

    bool isOk() const
    {
        return m_s2k;
    }

    Context *clone() const override
    {
        return new BotanPBKDFContext(provider(), type());
    }

    QCA::SymmetricKey makeKey(const QCA::SecureArray &         secret,
                              const QCA::InitializationVector &salt,
                              unsigned int                     keyLength,
                              unsigned int                     iterationCount) override
    {
        if (!m_s2k)
            return {};

        const std::string        secretString(secret.data(), secret.size());
        const Botan::OctetString key =
            m_s2k->derive_key(keyLength, secretString, (const Botan::byte *)salt.data(), salt.size(), iterationCount);
        const QCA::SecureArray retval(QByteArray((const char *)key.begin(), key.length()));
        return QCA::SymmetricKey(retval);
    }

    QCA::SymmetricKey makeKey(const QCA::SecureArray &         secret,
                              const QCA::InitializationVector &salt,
                              unsigned int                     keyLength,
                              int                              msecInterval,
                              unsigned int *                   iterationCount) override
    {
        Q_ASSERT(iterationCount != nullptr);
        Botan::OctetString key;
        QElapsedTimer      timer;
        const std::string  secretString(secret.data(), secret.size());

        *iterationCount = 0;
        timer.start();
        while (timer.elapsed() < msecInterval) {
            key = m_s2k->derive_key(keyLength, secretString, (const Botan::byte *)salt.data(), salt.size(), 1);
            ++(*iterationCount);
        }
        return makeKey(secret, salt, keyLength, *iterationCount);
    }

protected:
    Botan::S2K *m_s2k;
};

static QString qcaHkdfToBotanHkdf(const QString &type)
{
    if (type == QLatin1String("hkdf(sha256)"))
        return QStringLiteral("SHA-256");

    return {};
}

//-----------------------------------------------------------
class BotanHKDFContext : public QCA::HKDFContext
{
    Q_OBJECT
public:
    BotanHKDFContext(QCA::Provider *p, const QString &type)
        : QCA::HKDFContext(p, type)
    {
        const QString hashName = qcaHkdfToBotanHkdf(type);
        Botan::HMAC * hashObj;
        hashObj = new Botan::HMAC(Botan::HashFunction::create_or_throw(hashName.toStdString()).release());
        m_hkdf  = new Botan::HKDF(hashObj);
    }

    ~BotanHKDFContext() override
    {
        delete m_hkdf;
    }

    Context *clone() const override
    {
        return new BotanHKDFContext(provider(), type());
    }

    QCA::SymmetricKey makeKey(const QCA::SecureArray &         secret,
                              const QCA::InitializationVector &salt,
                              const QCA::InitializationVector &info,
                              unsigned int                     keyLength) override
    {
        Botan::secure_vector<uint8_t> key(keyLength);
        m_hkdf->kdf(key.data(),
                    keyLength,
                    reinterpret_cast<const Botan::byte *>(secret.data()),
                    secret.size(),
                    reinterpret_cast<const Botan::byte *>(salt.data()),
                    salt.size(),
                    reinterpret_cast<const Botan::byte *>(info.data()),
                    info.size());
        QCA::SecureArray retval(QByteArray::fromRawData(reinterpret_cast<const char *>(key.data()), key.size()));
        return QCA::SymmetricKey(retval);
    }

protected:
    Botan::HKDF *m_hkdf;
};

static void
qcaCipherToBotanCipher(const QString &type, std::string *algoName, std::string *algoMode, std::string *algoPadding)
{
    if (type == QLatin1String("aes128-ecb")) {
        *algoName    = "AES-128";
        *algoMode    = "ECB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("aes128-cbc")) {
        *algoName    = "AES-128";
        *algoMode    = "CBC";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("aes128-cfb")) {
        *algoName    = "AES-128";
        *algoMode    = "CFB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("aes128-ofb")) {
        *algoName    = "AES-128";
        *algoMode    = "OFB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("aes192-ecb")) {
        *algoName    = "AES-192";
        *algoMode    = "ECB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("aes192-cbc")) {
        *algoName    = "AES-192";
        *algoMode    = "CBC";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("aes192-cfb")) {
        *algoName    = "AES-192";
        *algoMode    = "CFB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("aes192-ofb")) {
        *algoName    = "AES-192";
        *algoMode    = "OFB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("aes256-ecb")) {
        *algoName    = "AES-256";
        *algoMode    = "ECB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("aes256-cbc")) {
        *algoName    = "AES-256";
        *algoMode    = "CBC";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("aes256-cfb")) {
        *algoName    = "AES-256";
        *algoMode    = "CFB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("aes256-ofb")) {
        *algoName    = "AES-256";
        *algoMode    = "OFB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("blowfish-ecb")) {
        *algoName    = "Blowfish";
        *algoMode    = "ECB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("blowfish-cbc")) {
        *algoName    = "Blowfish";
        *algoMode    = "CBC";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("blowfish-cbc-pkcs7")) {
        *algoName    = "Blowfish";
        *algoMode    = "CBC";
        *algoPadding = "PKCS7";
    } else if (type == QLatin1String("blowfish-cfb")) {
        *algoName    = "Blowfish";
        *algoMode    = "CFB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("blowfish-ofb")) {
        *algoName    = "Blowfish";
        *algoMode    = "OFB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("des-ecb")) {
        *algoName    = "DES";
        *algoMode    = "ECB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("des-ecb-pkcs7")) {
        *algoName    = "DES";
        *algoMode    = "ECB";
        *algoPadding = "PKCS7";
    } else if (type == QLatin1String("des-cbc")) {
        *algoName    = "DES";
        *algoMode    = "CBC";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("des-cbc-pkcs7")) {
        *algoName    = "DES";
        *algoMode    = "CBC";
        *algoPadding = "PKCS7";
    } else if (type == QLatin1String("des-cfb")) {
        *algoName    = "DES";
        *algoMode    = "CFB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("des-ofb")) {
        *algoName    = "DES";
        *algoMode    = "OFB";
        *algoPadding = "NoPadding";
    } else if (type == QLatin1String("tripledes-ecb")) {
        *algoName    = "TripleDES";
        *algoMode    = "ECB";
        *algoPadding = "NoPadding";
    }
}

static std::string qcaCipherToBotanCipher(const QString &qcaCipher)
{
    std::string algoName, algoMode, algoPadding;
    qcaCipherToBotanCipher(qcaCipher, &algoName, &algoMode, &algoPadding);
    return algoName + '/' + algoMode + '/' + algoPadding; // NOLINT(performance-inefficient-string-concatenation)
}

//-----------------------------------------------------------
class BotanCipherContext : public QCA::CipherContext
{
    Q_OBJECT
public:
    BotanCipherContext(QCA::Provider *p, const QString &type)
        : QCA::CipherContext(p, type)
    {
        qcaCipherToBotanCipher(type, &m_algoName, &m_algoMode, &m_algoPadding);
    }

    void setup(QCA::Direction                   dir,
               const QCA::SymmetricKey &        key,
               const QCA::InitializationVector &iv,
               const QCA::AuthTag &             tag) override
    {
        Q_UNUSED(tag);
        try {
            m_dir = dir;
            const Botan::SymmetricKey keyCopy((Botan::byte *)key.data(), key.size());

            if (iv.size() == 0) {
                if (QCA::Encode == dir) {
                    m_crypter = new Botan::Pipe(Botan::get_cipher(
                        m_algoName + '/' + m_algoMode + '/' + m_algoPadding, keyCopy, Botan::ENCRYPTION));
                } else {
                    m_crypter = new Botan::Pipe(Botan::get_cipher(
                        m_algoName + '/' + m_algoMode + '/' + m_algoPadding, keyCopy, Botan::DECRYPTION));
                }
            } else {
                const Botan::InitializationVector ivCopy((Botan::byte *)iv.data(), iv.size());
                if (QCA::Encode == dir) {
                    m_crypter = new Botan::Pipe(Botan::get_cipher(
                        m_algoName + '/' + m_algoMode + '/' + m_algoPadding, keyCopy, ivCopy, Botan::ENCRYPTION));
                } else {
                    m_crypter = new Botan::Pipe(Botan::get_cipher(
                        m_algoName + '/' + m_algoMode + '/' + m_algoPadding, keyCopy, ivCopy, Botan::DECRYPTION));
                }
            }
            m_crypter->start_msg();
        } catch (Botan::Exception &e) {
            m_crypter = nullptr;
            std::cout << "caught: " << e.what() << std::endl;
        }
    }

    Context *clone() const override
    {
        return new BotanCipherContext(*this);
    }

    int blockSize() const override
    {
        if (const std::unique_ptr<Botan::BlockCipher> bc = Botan::BlockCipher::create(m_algoName))
            return bc->block_size();

        throw Botan::Algorithm_Not_Found(m_algoName);
    }

    QCA::AuthTag tag() const override
    {
        // For future implementation
        return QCA::AuthTag();
    }

    bool update(const QCA::SecureArray &in, QCA::SecureArray *out) override
    {
        if (!m_crypter)
            return false;
        m_crypter->write((Botan::byte *)in.data(), in.size());
        QCA::SecureArray result(m_crypter->remaining());
        // Perhaps bytes_read is redundant and can be dropped
        const size_t bytes_read = m_crypter->read((Botan::byte *)result.data(), result.size());
        result.resize(bytes_read);
        *out = result;
        return true;
    }

    bool final(QCA::SecureArray *out) override
    {
        m_crypter->end_msg();
        QCA::SecureArray result(m_crypter->remaining());
        // Perhaps bytes_read is redundant and can be dropped
        const size_t bytes_read = m_crypter->read((Botan::byte *)result.data(), result.size());
        result.resize(bytes_read);
        *out = result;
        return true;
    }

    QCA::KeyLength keyLength() const override
    {
        Botan::Key_Length_Specification kls(0);
        if (const std::unique_ptr<Botan::BlockCipher> bc = Botan::BlockCipher::create(m_algoName))
            kls = bc->key_spec();
        else if (const std::unique_ptr<Botan::StreamCipher> sc = Botan::StreamCipher::create(m_algoName))
            kls = sc->key_spec();
        else if (const std::unique_ptr<Botan::MessageAuthenticationCode> mac =
                     Botan::MessageAuthenticationCode::create(m_algoName))
            kls = mac->key_spec();
        return QCA::KeyLength(kls.minimum_keylength(), kls.maximum_keylength(), kls.keylength_multiple());
    }

    ~BotanCipherContext() override
    {
        delete m_crypter;
    }

protected:
    QCA::Direction       m_dir;
    std::string          m_algoName;
    std::string          m_algoMode;
    std::string          m_algoPadding;
    Botan::Keyed_Filter *m_cipher;
    Botan::Pipe *        m_crypter;
};

//==========================================================
class botanProvider : public QCA::Provider
{
public:
    void init() override
    {
    }

    ~botanProvider() override
    {
        // We should be cleaning up there, but
        // this causes the unit tests to segfault
        // delete m_init;
    }

    int qcaVersion() const override
    {
        return QCA_VERSION;
    }

    QString name() const override
    {
        return QStringLiteral("qca-botan");
    }

    const QStringList &pbkdfTypes() const
    {
        static QStringList list;
        if (list.isEmpty()) {
            list += QStringLiteral("pbkdf1(sha1)");
            std::unique_ptr<BotanPBKDFContext> pbkdf1md2(new BotanPBKDFContext(nullptr, QStringLiteral("pbkdf1(md2)")));
            if (pbkdf1md2->isOk())
                list += QStringLiteral("pbkdf1(md2)");
            list += QStringLiteral("pbkdf2(sha1)");
        }
        return list;
    }

    const QStringList &hashTypes() const
    {
        static QStringList supported;
        if (supported.isEmpty()) {
            QStringList list;
            list += QStringLiteral("md2");
            list += QStringLiteral("md4");
            list += QStringLiteral("md5");
            list += QStringLiteral("sha1");
            list += QStringLiteral("sha256");
            list += QStringLiteral("sha384");
            list += QStringLiteral("sha512");
            list += QStringLiteral("ripemd160");

            for (const QString &hash : qAsConst(list)) {
                std::unique_ptr<BotanHashContext> hashContext(new BotanHashContext(nullptr, hash));
                if (hashContext->isOk()) {
                    supported << hash;
                }
            }
        }
        return supported;
    }

    const QStringList &cipherTypes() const
    {
        static QStringList supported;
        if (supported.isEmpty()) {
            QStringList list;
            list += QStringLiteral("aes128-ecb");
            list += QStringLiteral("aes128-cbc");
            list += QStringLiteral("aes128-cfb");
            list += QStringLiteral("aes128-ofb");
            list += QStringLiteral("aes192-ecb");
            list += QStringLiteral("aes192-cbc");
            list += QStringLiteral("aes192-cfb");
            list += QStringLiteral("aes192-ofb");
            list += QStringLiteral("aes256-ecb");
            list += QStringLiteral("aes256-cbc");
            list += QStringLiteral("aes256-cfb");
            list += QStringLiteral("aes256-ofb");
            list += QStringLiteral("des-ecb");
            list += QStringLiteral("des-ecb-pkcs7");
            list += QStringLiteral("des-cbc");
            list += QStringLiteral("des-cbc-pkcs7");
            list += QStringLiteral("des-cfb");
            list += QStringLiteral("des-ofb");
            list += QStringLiteral("tripledes-ecb");
            list += QStringLiteral("blowfish-ecb");
            list += QStringLiteral("blowfish-cbc");
            list += QStringLiteral("blowfish-cbc-pkcs7");
            list += QStringLiteral("blowfish-cfb");
            list += QStringLiteral("blowfish-ofb");

            for (const QString &cipher : qAsConst(list)) {
                const std::string bothanCipher = qcaCipherToBotanCipher(cipher);
                try {
                    std::unique_ptr<Botan::Keyed_Filter> enc(Botan::get_cipher(bothanCipher, Botan::ENCRYPTION));
                    std::unique_ptr<Botan::Keyed_Filter> dec(Botan::get_cipher(bothanCipher, Botan::DECRYPTION));
                    supported += cipher;
                } catch (Botan::Exception &e) {
                }
            }
        }
        return supported;
    }

    const QStringList &hmacTypes() const
    {
        static QStringList list;
        if (list.isEmpty()) {
            list += QStringLiteral("hmac(md5)");
            list += QStringLiteral("hmac(sha1)");
            // HMAC with SHA2 doesn't appear to work correctly in Botan.
            // list += QStringLiteral("hmac(sha256)");
            // list += QStringLiteral("hmac(sha384)");
            // list += QStringLiteral("hmac(sha512)");
            list += QStringLiteral("hmac(ripemd160)");
        }
        return list;
    }

    QStringList hkdfTypes() const
    {
        static QStringList list;
        if (list.isEmpty()) {
            list += QStringLiteral("hkdf(sha256)");
        }
        return list;
    }

    QStringList features() const override
    {
        static QStringList list;
        if (list.isEmpty()) {
            list += QStringLiteral("random");
            list += hmacTypes();
            list += pbkdfTypes();
            list += hkdfTypes();
            list += cipherTypes();
            list += hashTypes();
        }
        return list;
    }

    Context *createContext(const QString &type) override
    {
        if (type == QLatin1String("random"))
            return new botanRandomContext(this);
        else if (hashTypes().contains(type))
            return new BotanHashContext(this, type);
        else if (hmacTypes().contains(type))
            return new BotanHMACContext(this, type);
        else if (pbkdfTypes().contains(type))
            return new BotanPBKDFContext(this, type);
        else if (hkdfTypes().contains(type))
            return new BotanHKDFContext(this, type);
        else if (cipherTypes().contains(type))
            return new BotanCipherContext(this, type);
        else
            return nullptr;
    }

private:
};

class botanPlugin : public QObject, public QCAPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
    Q_INTERFACES(QCAPlugin)
public:
    QCA::Provider *createProvider() override
    {
        return new botanProvider;
    }
};

#include "qca-botan.moc"
