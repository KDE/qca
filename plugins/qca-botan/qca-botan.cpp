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
#include <QElapsedTimer>
#include <QtPlugin>

#include <qstringlist.h>

#include <botan/hmac.h>
#include <botan/version.h>
#include <botan/auto_rng.h>
#include <botan/block_cipher.h>
#include <botan/filters.h>
#include <botan/hash.h>
#include <botan/pbkdf.h>
#include <botan/hkdf.h>
#include <botan/stream_cipher.h>

#include <stdlib.h>
#include <iostream>

//-----------------------------------------------------------
class botanRandomContext : public QCA::RandomContext
{
public:
    botanRandomContext(QCA::Provider *p) : RandomContext(p)
    {
    }

    Context *clone() const override
    {
	return new botanRandomContext( *this );
    }

    QCA::SecureArray nextBytes(int size) override
    {
        QCA::SecureArray buf(size);
	Botan::AutoSeeded_RNG rng;
	rng.randomize(reinterpret_cast<Botan::byte*>(buf.data()), buf.size());
	return buf;
    }
};

static QString qcaHashToBotanHash(const QString &type)
{
    if ( type == "md2" )
	return QString("MD2");
    else if ( type == "md4" )
	return QString("MD4");
    else if ( type == "md5" )
	return QString("MD5");
    else if ( type == "sha1" )
	return QString("SHA-1");
    else if ( type == "sha256" )
	return QString("SHA-256");
    else if ( type == "sha384" )
	return QString("SHA-384");
    else if ( type == "sha512" )
	return QString("SHA-512");
    else if ( type == "ripemd160" )
	return QString("RIPEMD-160");

    return {};
}

//-----------------------------------------------------------
class BotanHashContext : public QCA::HashContext
{
public:
    BotanHashContext( QCA::Provider *p, const QString &type) : QCA::HashContext(p, type)
    {
	const QString hashName = qcaHashToBotanHash(type);
	m_hashObj = Botan::HashFunction::create(hashName.toStdString()).release();
    }

    ~BotanHashContext()
    {
	delete m_hashObj;
    }

    bool isOk() const
    {
	return m_hashObj;
    }

    Context *clone() const override
    {
	return new BotanHashContext(*this);
    }

    void clear() override
    {
	m_hashObj->clear();
    }

    void update(const QCA::MemoryRegion &a) override
    {
	m_hashObj->update( (const Botan::byte*)a.data(), a.size() );
    }

    QCA::MemoryRegion final() override
    {
	QCA::SecureArray a( m_hashObj->output_length() );
	m_hashObj->final( (Botan::byte *)a.data() );
	return a;
    }

private:
    Botan::HashFunction *m_hashObj;
};


//-----------------------------------------------------------
class BotanHMACContext : public QCA::MACContext
{
public:
    BotanHMACContext( const QString &hashName, QCA::Provider *p, const QString &type) : QCA::MACContext(p, type)
    {
	m_hashObj = new Botan::HMAC(Botan::HashFunction::create_or_throw(hashName.toStdString()).release());
	if (0 == m_hashObj) {
	    std::cout << "null context object" << std::endl;
	}
    }

    ~BotanHMACContext()
    {
    }

    void setup(const QCA::SymmetricKey &key) override
    {
	// this often gets called with an empty key, because that is the default
	// in the QCA MessageAuthenticationCode constructor. Botan doesn't like
	// that happening.
	if (key.size() > 0) {
	    m_hashObj->set_key( (const Botan::byte *)key.data(), key.size() );
	}
    }

    Context *clone() const override
    {
	return new BotanHMACContext(*this);
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
	m_hashObj->update( (const Botan::byte*)a.data(), a.size() );
    }

    void final( QCA::MemoryRegion *out) override
    {
	QCA::SecureArray sa( m_hashObj->output_length(), 0 );
	m_hashObj->final( (Botan::byte *)sa.data() );
	*out = sa;
    }

protected:
    Botan::HMAC *m_hashObj;
};


//-----------------------------------------------------------
class BotanPBKDFContext: public QCA::KDFContext
{
public:
    BotanPBKDFContext( const QString &kdfName, QCA::Provider *p, const QString &type) : QCA::KDFContext(p, type)
    {
	try {
	    m_s2k = Botan::get_s2k(kdfName.toStdString());
	} catch (Botan::Exception& e) {
	    m_s2k = nullptr;
	}
    }

    ~BotanPBKDFContext() 
    {
	delete m_s2k;
    }

    bool isOk() const
    {
	return m_s2k;
    }

    Context *clone() const override
    {
	return new BotanPBKDFContext( *this );
    }

    QCA::SymmetricKey makeKey(const QCA::SecureArray &secret, const QCA::InitializationVector &salt,
			      unsigned int keyLength, unsigned int iterationCount) override
    {
	if (!m_s2k)
	    return {};

	std::string secretString(secret.data(), secret.size() );
	Botan::OctetString key = m_s2k->derive_key(keyLength, secretString, (const Botan::byte*)salt.data(), salt.size(), iterationCount);
        QCA::SecureArray retval(QByteArray((const char*)key.begin(), key.length()));
	return QCA::SymmetricKey(retval);
    }

	QCA::SymmetricKey makeKey(const QCA::SecureArray &secret,
							  const QCA::InitializationVector &salt,
							  unsigned int keyLength,
							  int msecInterval,
							  unsigned int *iterationCount) override
	{
		Q_ASSERT(iterationCount != NULL);
		Botan::OctetString key;
		QElapsedTimer timer;
		std::string secretString(secret.data(), secret.size() );

		*iterationCount = 0;
		timer.start();
		while (timer.elapsed() < msecInterval) {
			key = m_s2k->derive_key(keyLength,
									secretString,
									(const Botan::byte*)salt.data(),
									salt.size(),
									1);
			++(*iterationCount);
		}
		return makeKey(secret, salt, keyLength, *iterationCount);
	}

protected:
    Botan::S2K* m_s2k;
};

//-----------------------------------------------------------
class BotanHKDFContext: public QCA::HKDFContext
{
public:
    BotanHKDFContext(const QString &hashName, QCA::Provider *p, const QString &type) : QCA::HKDFContext(p, type)
    {
	Botan::HMAC *hashObj;
	hashObj = new Botan::HMAC(Botan::HashFunction::create_or_throw(hashName.toStdString()).release());
	m_hkdf = new Botan::HKDF(hashObj);
    }

    ~BotanHKDFContext()
    {
	delete m_hkdf;
    }

    Context *clone() const override
    {
	return new BotanHKDFContext( *this );
    }

    QCA::SymmetricKey makeKey(const QCA::SecureArray &secret, const QCA::InitializationVector &salt,
			      const QCA::InitializationVector &info, unsigned int keyLength) override
    {
	std::string secretString(secret.data(), secret.size());
	Botan::secure_vector<uint8_t> key(keyLength);
	m_hkdf->kdf(key.data(), keyLength,
		    reinterpret_cast<const Botan::byte*>(secret.data()), secret.size(),
		    reinterpret_cast<const Botan::byte*>(salt.data()), salt.size(),
		    reinterpret_cast<const Botan::byte*>(info.data()), info.size());
	QCA::SecureArray retval(QByteArray::fromRawData(reinterpret_cast<const char*>(key.data()), key.size()));
	return QCA::SymmetricKey(retval);
    }

protected:
    Botan::HKDF* m_hkdf;
};

static void qcaCipherToBotanCipher(const QString &type, std::string *algoName, std::string *algoMode, std::string *algoPadding)
{
    if (type == "aes128-ecb" ) {
	*algoName = "AES-128";
	*algoMode = "ECB";
	*algoPadding = "NoPadding";
    } else if ( type == "aes128-cbc" ) {
	*algoName = "AES-128";
	*algoMode = "CBC";
	*algoPadding = "NoPadding";
    } else if ( type == "aes128-cfb" ) {
	*algoName = "AES-128";
	*algoMode = "CFB";
	*algoPadding = "NoPadding";
    } else if ( type == "aes128-ofb" ) {
	*algoName = "AES-128";
	*algoMode = "OFB";
	*algoPadding = "NoPadding";
    } else if ( type == "aes192-ecb" ) {
	*algoName = "AES-192";
	*algoMode = "ECB";
	*algoPadding = "NoPadding";
    } else if ( type == "aes192-cbc" ) {
	*algoName = "AES-192";
	*algoMode = "CBC";
	*algoPadding = "NoPadding";
    } else if ( type == "aes192-cfb" ) {
	*algoName = "AES-192";
	*algoMode = "CFB";
	*algoPadding = "NoPadding";
    } else if ( type == "aes192-ofb" ) {
	*algoName = "AES-192";
	*algoMode = "OFB";
	*algoPadding = "NoPadding";
    } else if ( type == "aes256-ecb" ) {
	*algoName = "AES-256";
	*algoMode = "ECB";
	*algoPadding = "NoPadding";
    } else if ( type == "aes256-cbc" ) {
	*algoName = "AES-256";
	*algoMode = "CBC";
	*algoPadding = "NoPadding";
    } else if ( type == "aes256-cfb" ) {
	*algoName = "AES-256";
	*algoMode = "CFB";
	*algoPadding = "NoPadding";
    } else if ( type == "aes256-ofb" ) {
	*algoName = "AES-256";
	*algoMode = "OFB";
	*algoPadding = "NoPadding";
    } else if ( type == "blowfish-ecb" ) {
	*algoName = "Blowfish";
	*algoMode = "ECB";
	*algoPadding = "NoPadding";
    } else if ( type == "blowfish-cbc" ) {
	*algoName = "Blowfish";
	*algoMode = "CBC";
	*algoPadding = "NoPadding";
    } else if ( type == "blowfish-cbc-pkcs7" ) {
	*algoName = "Blowfish";
	*algoMode = "CBC";
	*algoPadding = "PKCS7";
    } else if ( type == "blowfish-cfb" ) {
	*algoName = "Blowfish";
	*algoMode = "CFB";
	*algoPadding = "NoPadding";
    } else if ( type == "blowfish-ofb" ) {
	*algoName = "Blowfish";
	*algoMode = "OFB";
	*algoPadding = "NoPadding";
    } else if ( type == "des-ecb" ) {
	*algoName = "DES";
	*algoMode = "ECB";
	*algoPadding = "NoPadding";
    } else if ( type == "des-ecb-pkcs7" ) {
	*algoName = "DES";
	*algoMode = "ECB";
	*algoPadding = "PKCS7";
    } else if ( type == "des-cbc" ) {
	*algoName = "DES";
	*algoMode = "CBC";
	*algoPadding = "NoPadding";
    } else if ( type == "des-cbc-pkcs7" ) {
	*algoName = "DES";
	*algoMode = "CBC";
	*algoPadding = "PKCS7";
    } else if ( type == "des-cfb" ) {
	*algoName = "DES";
	*algoMode = "CFB";
	*algoPadding = "NoPadding";
    } else if ( type == "des-ofb" ) {
	*algoName = "DES";
	*algoMode = "OFB";
	*algoPadding = "NoPadding";
    } else if ( type == "tripledes-ecb" ) {
	*algoName = "TripleDES";
	*algoMode = "ECB";
	*algoPadding = "NoPadding";
    }
}

//-----------------------------------------------------------
class BotanCipherContext : public QCA::CipherContext
{
public:
    BotanCipherContext( QCA::Provider *p, const QString &type) : QCA::CipherContext(p, type)
    {
	qcaCipherToBotanCipher( type, &m_algoName, &m_algoMode, &m_algoPadding );
    }

    void setup(QCA::Direction dir,
               const QCA::SymmetricKey &key,
               const QCA::InitializationVector &iv,
               const QCA::AuthTag &tag) override
    {
	Q_UNUSED(tag);
	try {
	m_dir = dir;
	Botan::SymmetricKey keyCopy((Botan::byte*)key.data(), key.size());

	if (iv.size() == 0) {
	    if (QCA::Encode == dir) {
		m_crypter = new Botan::Pipe(Botan::get_cipher(m_algoName+'/'+m_algoMode+'/'+m_algoPadding,
							      keyCopy, Botan::ENCRYPTION));
	    }
	    else {
		m_crypter = new Botan::Pipe(Botan::get_cipher(m_algoName+'/'+m_algoMode+'/'+m_algoPadding,
							      keyCopy, Botan::DECRYPTION));
	    }
	} else {
	    Botan::InitializationVector ivCopy((Botan::byte*)iv.data(), iv.size());
	    if (QCA::Encode == dir) {
		m_crypter = new Botan::Pipe(Botan::get_cipher(m_algoName+'/'+m_algoMode+'/'+m_algoPadding,
							      keyCopy, ivCopy, Botan::ENCRYPTION));
	    }
	    else {
		m_crypter = new Botan::Pipe(Botan::get_cipher(m_algoName+'/'+m_algoMode+'/'+m_algoPadding,
							      keyCopy, ivCopy, Botan::DECRYPTION));
	    }
	}
	m_crypter->start_msg();
	} catch (Botan::Exception& e) {
	    m_crypter = nullptr;
	    std::cout << "caught: " << e.what() << std::endl;
	}
    }

    Context *clone() const override
    {
	return new BotanCipherContext( *this );
    }

    int blockSize() const override
    {
	if(const std::unique_ptr<Botan::BlockCipher> bc = Botan::BlockCipher::create(m_algoName))
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
	m_crypter->write((Botan::byte*)in.data(), in.size());
	QCA::SecureArray result( m_crypter->remaining() );
	// Perhaps bytes_read is redundant and can be dropped
	size_t bytes_read = m_crypter->read((Botan::byte*)result.data(), result.size());
	result.resize(bytes_read);
        *out = result;
        return true;
    }

    bool final(QCA::SecureArray *out) override
    {
	m_crypter->end_msg();
	QCA::SecureArray result( m_crypter->remaining() );
	// Perhaps bytes_read is redundant and can be dropped
	size_t bytes_read = m_crypter->read((Botan::byte*)result.data(), result.size());
	result.resize(bytes_read);
        *out = result;
        return true;
    }

    QCA::KeyLength keyLength() const override
    {
        Botan::Key_Length_Specification kls(0);
        if(const std::unique_ptr<Botan::BlockCipher> bc = Botan::BlockCipher::create(m_algoName))
            kls = bc->key_spec();
        else if(const std::unique_ptr<Botan::StreamCipher> sc = Botan::StreamCipher::create(m_algoName))
            kls = sc->key_spec();
        else if(const std::unique_ptr<Botan::MessageAuthenticationCode> mac = Botan::MessageAuthenticationCode::create(m_algoName))
            kls = mac->key_spec();
        return QCA::KeyLength( kls.minimum_keylength(),
                               kls.maximum_keylength(),
                               kls.keylength_multiple() );
    }


    ~BotanCipherContext()
    {
	delete m_crypter;
    }

protected:
    QCA::Direction m_dir;
    std::string m_algoName;
    std::string m_algoMode;
    std::string m_algoPadding;
    Botan::Keyed_Filter *m_cipher;
    Botan::Pipe *m_crypter;
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

//==========================================================
class botanProvider : public QCA::Provider
{
public:
    void init() override
    {
    }

    ~botanProvider()
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
	return "qca-botan";
    }

    const QStringList &pbkdfTypes() const
    {
	static QStringList list;
	if (list.isEmpty()) {
	    list += "pbkdf1(sha1)";
	    std::unique_ptr<BotanPBKDFContext> pbkdf1md2(new BotanPBKDFContext( qcaPbkdfToBotanPbkdf("pbkdf1(md2)"), nullptr, "pbkdf1(md2)"));
	    if (pbkdf1md2->isOk())
		list += "pbkdf1(md2)";
	    list += "pbkdf2(sha1)";
	}
	return list;
    }

    const QStringList &hashTypes() const
    {
	static QStringList supported;
	if (supported.isEmpty()) {
	    QStringList list;
	    list += "md2";
	    list += "md4";
	    list += "md5";
	    list += "sha1";
	    list += "sha256";
	    list += "sha384";
	    list += "sha512";
	    list += "ripemd160";

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
	    list += "aes128-ecb";
	    list += "aes128-cbc";
	    list += "aes128-cfb";
	    list += "aes128-ofb";
	    list += "aes192-ecb";
	    list += "aes192-cbc";
	    list += "aes192-cfb";
	    list += "aes192-ofb";
	    list += "aes256-ecb";
	    list += "aes256-cbc";
	    list += "aes256-cfb";
	    list += "aes256-ofb";
	    list += "des-ecb";
	    list += "des-ecb-pkcs7";
	    list += "des-cbc";
	    list += "des-cbc-pkcs7";
	    list += "des-cfb";
	    list += "des-ofb";
	    list += "tripledes-ecb";
	    list += "blowfish-ecb";
	    list += "blowfish-cbc";
	    list += "blowfish-cbc-pkcs7";
	    list += "blowfish-cfb";
	    list += "blowfish-ofb";

	    for (const QString &cipher : qAsConst(list)) {
		std::string algoName, algoMode, algoPadding;
		qcaCipherToBotanCipher(cipher, &algoName, &algoMode, &algoPadding);
		try {
		    std::unique_ptr<Botan::Keyed_Filter> enc(Botan::get_cipher(algoName+'/'+algoMode+'/'+algoPadding, Botan::ENCRYPTION));
		    std::unique_ptr<Botan::Keyed_Filter> dec(Botan::get_cipher(algoName+'/'+algoMode+'/'+algoPadding, Botan::DECRYPTION));
		    supported += cipher;
		} catch (Botan::Exception& e) {
		}
	    }
	}
	return supported;
    }

    QStringList features() const override
    {
	static QStringList list;
	if (list.isEmpty()) {
	    list += "random";
	    list += "hmac(md5)";
	    list += "hmac(sha1)";
	    // HMAC with SHA2 doesn't appear to work correctly in Botan.
	    // list += "hmac(sha256)";
	    // list += "hmac(sha384)";
	    // list += "hmac(sha512)";
	    list += "hmac(ripemd160)";
	    list += pbkdfTypes();
	    list += "hkdf(sha256)";
	    list += cipherTypes();
	    list += hashTypes();
	}
	return list;
    }

    Context *createContext(const QString &type) override
    {
	if ( type == "random" )
	    return new botanRandomContext( this );
	else if ( hashTypes().contains(type) )
	    return new BotanHashContext( this, type );
	else if ( type == "hmac(md5)" )
	    return new BotanHMACContext( QString("MD5"), this, type );
	else if ( type == "hmac(sha1)" )
	    return new BotanHMACContext( QString("SHA-1"), this, type );
	else if ( type == "hmac(sha256)" )
	    return new BotanHMACContext( QString("SHA-256"), this, type );
	else if ( type == "hmac(sha384)" )
	    return new BotanHMACContext( QString("SHA-384"), this, type );
	else if ( type == "hmac(sha512)" )
	    return new BotanHMACContext( QString("SHA-512"), this, type );
	else if ( type == "hmac(ripemd160)" )
	    return new BotanHMACContext( QString("RIPEMD-160"), this, type );
	else if ( pbkdfTypes().contains(type) )
	    return new BotanPBKDFContext( qcaPbkdfToBotanPbkdf(type), this, type );
	else if ( type == "hkdf(sha256)" )
	    return new BotanHKDFContext( QString("SHA-256"), this, type );
	else if ( cipherTypes().contains( type ) )
	    return new BotanCipherContext( this, type );
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
	QCA::Provider *createProvider() override { return new botanProvider; }
};

#include "qca-botan.moc"
