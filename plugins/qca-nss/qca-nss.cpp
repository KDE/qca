/*
 * Copyright (C) 2006  Brad Hards <bradh@frogmouth.net>
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
#include "hasht.h"
#include "nss.h"
#include "pk11func.h"

#include <QtCrypto>

#include <QDebug>
#include <QStringList>
#include <QtPlugin>

//-----------------------------------------------------------
class nssHashContext : public QCA::HashContext
{
    Q_OBJECT
public:
    nssHashContext(QCA::Provider *p, const QString &type)
        : QCA::HashContext(p, type)
    {
        SECStatus s;

        NSS_NoDB_Init(".");

        m_status = 0;

        /* Get a slot to use for the crypto operations */
        m_slot = PK11_GetInternalKeySlot();
        if (!m_slot) {
            qDebug() << "GetInternalKeySlot failed";
            m_status = 1;
            return;
        }

        if (QLatin1String("md2") == type) {
            m_hashAlgo = SEC_OID_MD2;
        } else if (QLatin1String("md5") == type) {
            m_hashAlgo = SEC_OID_MD5;
        } else if (QLatin1String("sha1") == type) {
            m_hashAlgo = SEC_OID_SHA1;
        } else if (QLatin1String("sha256") == type) {
            m_hashAlgo = SEC_OID_SHA256;
        } else if (QLatin1String("sha384") == type) {
            m_hashAlgo = SEC_OID_SHA384;
        } else if (QLatin1String("sha512") == type) {
            m_hashAlgo = SEC_OID_SHA512;
        } else {
            qDebug() << "Unknown provider type: " << type;
            return; /* this will probably cause a segfault... */
        }

        m_context = PK11_CreateDigestContext(m_hashAlgo);
        if (!m_context) {
            qDebug() << "CreateDigestContext failed";
            return;
        }

        s = PK11_DigestBegin(m_context);
        if (s != SECSuccess) {
            qDebug() << "DigestBegin failed";
            return;
        }
    }

    ~nssHashContext() override
    {
        PK11_DestroyContext(m_context, PR_TRUE);
        if (m_slot)
            PK11_FreeSlot(m_slot);
    }

    Context *clone() const override
    {
        return new nssHashContext(provider(), type());
    }

    void clear() override
    {
        SECStatus s;

        PK11_DestroyContext(m_context, PR_TRUE);

        m_context = PK11_CreateDigestContext(m_hashAlgo);
        if (!m_context) {
            qDebug() << "CreateDigestContext failed";
            return;
        }

        s = PK11_DigestBegin(m_context);
        if (s != SECSuccess) {
            qDebug() << "DigestBegin failed";
            return;
        }
    }

    void update(const QCA::MemoryRegion &a) override
    {
        PK11_DigestOp(m_context, (const unsigned char *)a.data(), a.size());
    }

    QCA::MemoryRegion final() override
    {
        unsigned int     len = 0;
        QCA::SecureArray a(64);
        PK11_DigestFinal(m_context, (unsigned char *)a.data(), &len, a.size());
        a.resize(len);
        return a;
    }

private:
    PK11SlotInfo *m_slot;
    int           m_status;
    PK11Context * m_context;
    SECOidTag     m_hashAlgo;
};

//-----------------------------------------------------------
class nssHmacContext : public QCA::MACContext
{
    Q_OBJECT
public:
    nssHmacContext(QCA::Provider *p, const QString &type)
        : QCA::MACContext(p, type)
    {
        NSS_NoDB_Init(".");

        m_context = nullptr;
        m_status  = 0;

        /* Get a slot to use for the crypto operations */
        m_slot = PK11_GetInternalKeySlot();
        if (!m_slot) {
            qDebug() << "GetInternalKeySlot failed";
            m_status = 1;
            return;
        }

        if (QLatin1String("hmac(md5)") == type) {
            m_macAlgo = CKM_MD5_HMAC;
        } else if (QLatin1String("hmac(sha1)") == type) {
            m_macAlgo = CKM_SHA_1_HMAC;
        } else if (QLatin1String("hmac(sha256)") == type) {
            m_macAlgo = CKM_SHA256_HMAC;
        } else if (QLatin1String("hmac(sha384)") == type) {
            m_macAlgo = CKM_SHA384_HMAC;
        } else if (QLatin1String("hmac(sha512)") == type) {
            m_macAlgo = CKM_SHA512_HMAC;
        } else if (QLatin1String("hmac(ripemd160)") == type) {
            m_macAlgo = CKM_RIPEMD160_HMAC;
        } else {
            qDebug() << "Unknown provider type: " << type;
            return; /* this will probably cause a segfault... */
        }
    }

    ~nssHmacContext() override
    {
        if (m_context)
            PK11_DestroyContext(m_context, PR_TRUE);
        if (m_slot)
            PK11_FreeSlot(m_slot);
    }

    Context *clone() const override
    {
        return new nssHmacContext(provider(), type());
    }

    void clear()
    {
        PK11_DestroyContext(m_context, PR_TRUE);

        SECItem noParams;
        noParams.data = nullptr;
        noParams.len  = 0;

        m_context = PK11_CreateContextBySymKey(m_macAlgo, CKA_SIGN, m_nssKey, &noParams);
        if (!m_context) {
            qDebug() << "CreateContextBySymKey failed";
            return;
        }

        SECStatus s = PK11_DigestBegin(m_context);
        if (s != SECSuccess) {
            qDebug() << "DigestBegin failed";
            return;
        }
    }

    QCA::KeyLength keyLength() const override
    {
        return anyKeyLength();
    }

    void setup(const QCA::SymmetricKey &key) override
    {
        /* turn the raw key into a SECItem */
        SECItem keyItem;
        keyItem.data = (unsigned char *)key.data();
        keyItem.len  = key.size();

        m_nssKey = PK11_ImportSymKey(m_slot, m_macAlgo, PK11_OriginUnwrap, CKA_SIGN, &keyItem, nullptr);

        SECItem noParams;
        noParams.data = nullptr;
        noParams.len  = 0;

        m_context = PK11_CreateContextBySymKey(m_macAlgo, CKA_SIGN, m_nssKey, &noParams);
        if (!m_context) {
            qDebug() << "CreateContextBySymKey failed";
            return;
        }

        SECStatus s = PK11_DigestBegin(m_context);
        if (s != SECSuccess) {
            qDebug() << "DigestBegin failed";
            return;
        }
    }

    void update(const QCA::MemoryRegion &a) override
    {
        PK11_DigestOp(m_context, (const unsigned char *)a.data(), a.size());
    }

    void final(QCA::MemoryRegion *out) override
    {
        // NSS doesn't appear to be able to tell us how big the digest will
        // be for a given algorithm until after we finalise it, so we work
        // around the problem a bit.
        QCA::SecureArray sa(HASH_LENGTH_MAX, 0); // assume the biggest hash size we know
        unsigned int     len = 0;
        PK11_DigestFinal(m_context, (unsigned char *)sa.data(), &len, sa.size());
        sa.resize(len); // and fix it up later
        *out = sa;
    }

private:
    PK11SlotInfo *    m_slot;
    int               m_status;
    PK11Context *     m_context;
    CK_MECHANISM_TYPE m_macAlgo;
    PK11SymKey *      m_nssKey;
};

//-----------------------------------------------------------
class nssCipherContext : public QCA::CipherContext
{
    Q_OBJECT
public:
    nssCipherContext(QCA::Provider *p, const QString &type)
        : QCA::CipherContext(p, type)
    {
        NSS_NoDB_Init(".");

        if (QLatin1String("aes128-ecb") == type) {
            m_cipherMechanism = CKM_AES_ECB;
        } else if (QLatin1String("aes128-cbc") == type) {
            m_cipherMechanism = CKM_AES_CBC;
        } else if (QLatin1String("des-ecb") == type) {
            m_cipherMechanism = CKM_DES_ECB;
        } else if (QLatin1String("des-cbc") == type) {
            m_cipherMechanism = CKM_DES_CBC;
        } else if (QLatin1String("des-cbc-pkcs7") == type) {
            m_cipherMechanism = CKM_DES_CBC_PAD;
        } else if (QLatin1String("tripledes-ecb") == type) {
            m_cipherMechanism = CKM_DES3_ECB;
        } else {
            qDebug() << "Unknown provider type: " << type;
            return; /* this will probably cause a segfault... */
        }
    }

    ~nssCipherContext() override
    {
    }

    void setup(QCA::Direction                   dir,
               const QCA::SymmetricKey &        key,
               const QCA::InitializationVector &iv,
               const QCA::AuthTag &             tag) override
    {
        Q_UNUSED(tag);
        /* Get a slot to use for the crypto operations */
        m_slot = PK11_GetBestSlot(m_cipherMechanism, nullptr);
        if (!m_slot) {
            qDebug() << "GetBestSlot failed";
            return;
        }

        /* turn the raw key into a SECItem */
        SECItem keyItem;
        keyItem.data = (unsigned char *)key.data();
        keyItem.len  = key.size();

        if (QCA::Encode == dir) {
            m_nssKey = PK11_ImportSymKey(m_slot, m_cipherMechanism, PK11_OriginUnwrap, CKA_ENCRYPT, &keyItem, nullptr);
        } else {
            // decryption
            m_nssKey = PK11_ImportSymKey(m_slot, m_cipherMechanism, PK11_OriginUnwrap, CKA_DECRYPT, &keyItem, nullptr);
        }

        SECItem ivItem;
        ivItem.data = (unsigned char *)iv.data();
        ivItem.len  = iv.size();

        m_params = PK11_ParamFromIV(m_cipherMechanism, &ivItem);

        if (QCA::Encode == dir) {
            m_context = PK11_CreateContextBySymKey(m_cipherMechanism, CKA_ENCRYPT, m_nssKey, m_params);
        } else {
            // decryption
            m_context = PK11_CreateContextBySymKey(m_cipherMechanism, CKA_DECRYPT, m_nssKey, m_params);
        }

        if (!m_context) {
            qDebug() << "CreateContextBySymKey failed";
            return;
        }
    }

    QCA::Provider::Context *clone() const override
    {
        return new nssCipherContext(*this);
    }

    int blockSize() const override
    {
        return PK11_GetBlockSize(m_cipherMechanism, m_params);
    }

    QCA::AuthTag tag() const override
    {
        // For future implementation
        return QCA::AuthTag();
    }

    bool update(const QCA::SecureArray &in, QCA::SecureArray *out) override
    {
        out->resize(in.size() + blockSize());
        int resultLength;

        PK11_CipherOp(
            m_context, (unsigned char *)out->data(), &resultLength, out->size(), (unsigned char *)in.data(), in.size());
        out->resize(resultLength);

        return true;
    }

    bool final(QCA::SecureArray *out) override
    {
        out->resize(blockSize());
        unsigned int resultLength;

        PK11_DigestFinal(m_context, (unsigned char *)out->data(), &resultLength, out->size());
        out->resize(resultLength);

        return true;
    }

    QCA::KeyLength keyLength() const override
    {
        int min      = 0;
        int max      = 0;
        int multiple = 0;

        switch (m_cipherMechanism) {
        case CKM_AES_ECB:
        case CKM_AES_CBC:
            min = max = 16;
            multiple  = 1;
            break;

        case CKM_DES_ECB:
        case CKM_DES_CBC:
        case CKM_DES_CBC_PAD:
            min = max = 8;
            multiple  = 1;
            break;

        case CKM_DES3_ECB:
            min      = 16;
            max      = 24;
            multiple = 1;
            break;
        }

        return QCA::KeyLength(min, max, multiple);
    }

private:
    PK11SymKey *      m_nssKey;
    CK_MECHANISM_TYPE m_cipherMechanism;
    PK11SlotInfo *    m_slot;
    PK11Context *     m_context;
    SECItem *         m_params;
};

//==========================================================
class nssProvider : public QCA::Provider
{
public:
    void init() override
    {
    }

    ~nssProvider() override
    {
    }

    int qcaVersion() const override
    {
        return QCA_VERSION;
    }

    QString name() const override
    {
        return QStringLiteral("qca-nss");
    }

    QStringList features() const override
    {
        QStringList list;

        list += QStringLiteral("md2");
        list += QStringLiteral("md5");
        list += QStringLiteral("sha1");
        list += QStringLiteral("sha256");
        list += QStringLiteral("sha384");
        list += QStringLiteral("sha512");

        list += QStringLiteral("hmac(md5)");
        list += QStringLiteral("hmac(sha1)");
        list += QStringLiteral("hmac(sha256)");
        list += QStringLiteral("hmac(sha384)");
        list += QStringLiteral("hmac(sha512)");
        // appears to not be implemented in NSS yet
        // list += QStringLiteral("hmac(ripemd160)");

        list += QStringLiteral("aes128-ecb");
        list += QStringLiteral("aes128-cbc");
        list += QStringLiteral("des-ecb");
        list += QStringLiteral("des-cbc");
        list += QStringLiteral("des-cbc-pkcs7");
        list += QStringLiteral("tripledes-ecb");

        return list;
    }

    Context *createContext(const QString &type) override
    {
        if (type == QLatin1String("md2"))
            return new nssHashContext(this, type);
        if (type == QLatin1String("md5"))
            return new nssHashContext(this, type);
        if (type == QLatin1String("sha1"))
            return new nssHashContext(this, type);
        if (type == QLatin1String("sha256"))
            return new nssHashContext(this, type);
        if (type == QLatin1String("sha384"))
            return new nssHashContext(this, type);
        if (type == QLatin1String("sha512"))
            return new nssHashContext(this, type);

        if (type == QLatin1String("hmac(md5)"))
            return new nssHmacContext(this, type);
        if (type == QLatin1String("hmac(sha1)"))
            return new nssHmacContext(this, type);
        if (type == QLatin1String("hmac(sha256)"))
            return new nssHmacContext(this, type);
        if (type == QLatin1String("hmac(sha384)"))
            return new nssHmacContext(this, type);
        if (type == QLatin1String("hmac(sha512)"))
            return new nssHmacContext(this, type);
        if (type == QLatin1String("hmac(ripemd160)"))
            return new nssHmacContext(this, type);

        if (type == QLatin1String("aes128-ecb"))
            return new nssCipherContext(this, type);
        if (type == QLatin1String("aes128-cbc"))
            return new nssCipherContext(this, type);
        if (type == QLatin1String("des-ecb"))
            return new nssCipherContext(this, type);
        if (type == QLatin1String("des-cbc"))
            return new nssCipherContext(this, type);
        if (type == QLatin1String("des-cbc-pkcs7"))
            return new nssCipherContext(this, type);
        if (type == QLatin1String("tripledes-ecb"))
            return new nssCipherContext(this, type);
        else
            return nullptr;
    }
};

class nssPlugin : public QObject, public QCAPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
    Q_INTERFACES(QCAPlugin)
public:
    QCA::Provider *createProvider() override
    {
        return new nssProvider;
    }
};

#include "qca-nss.moc"
