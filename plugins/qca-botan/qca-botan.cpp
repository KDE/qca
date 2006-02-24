/*
 * Copyright (C) 2004  Justin Karneges
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include <QtCrypto>
#include <QtCore>

#include <qstringlist.h>

#include <botan/botan.h>
#include <botan/hmac.h>
#include <botan/s2k.h>

#include <stdlib.h>
#include <iostream>

//-----------------------------------------------------------
class botanRandomContext : public QCA::RandomContext
{
public:
    botanRandomContext(QCA::Provider *p) : RandomContext(p)
    {
    }
	
    Context *clone() const
    {
	return new botanRandomContext( *this );
    }
    
    QSecureArray nextBytes(int size, QCA::Random::Quality quality)
    {
	QSecureArray buf(size);
	Botan::Global_RNG::randomize( (Botan::byte*)buf.data(), buf.size(), lookup_quality(quality) );
	return buf;
    }

private:
    Botan::RNG_Quality lookup_quality( QCA::Random::Quality quality )
    {
	if ( QCA::Random::Nonce == quality )
	    return Botan::Nonce;
	else if ( QCA::Random::PublicValue == quality )
	    return Botan::PublicValue;
	else if ( QCA::Random::SessionKey == quality )
	    return Botan::SessionKey;
	else if ( QCA::Random::LongTermKey == quality )
	    return Botan::LongTermKey;
	else
	    // this can't happen, but insurance against an accidental
	    // addition of a value to the enum
	    return Botan::SessionKey;
    }
};


//-----------------------------------------------------------
class BotanHashContext : public QCA::HashContext
{
public:
    BotanHashContext( QString hashName, QCA::Provider *p, const QString &type) : QCA::HashContext(p, type)
    {
	m_hashObj = Botan::get_hash(hashName.toStdString());
    }

    ~BotanHashContext()
    {
	delete m_hashObj;
    }

    Context *clone() const
    {
	return new BotanHashContext(*this);
    }

    void clear()
    {
	m_hashObj->clear();
    }
    
    void update(const QSecureArray &a)
    {
	m_hashObj->update( (const Botan::byte*)a.data(), a.size() );
    }
    
    QSecureArray final()
    {
	QSecureArray a( m_hashObj->OUTPUT_LENGTH );
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
    BotanHMACContext( QString hashName, QCA::Provider *p, const QString &type) : QCA::MACContext(p, type)
    {
	m_hashObj = new Botan::HMAC(hashName.toStdString());
	if (0 == m_hashObj) {
	    std::cout << "null context object" << std::endl;
	}
    }

    ~BotanHMACContext()
    {
    }

    void setup(const QCA::SymmetricKey &key)
    {
	// this often gets called with an empty key, because that is the default
	// in the QCA MessageAuthenticationCode constructor. Botan doesn't like
	// that happening.
	if (key.size() > 0) {
	    m_hashObj->set_key( (const Botan::byte *)key.data(), key.size() );
	}
    }

    Context *clone() const
    {
	return new BotanHMACContext(*this);
    }

    void clear()
    {
	m_hashObj->clear();
    }

    QCA::KeyLength keyLength() const
    {
        return anyKeyLength();
    }

    void update(const QSecureArray &a)
    {
	m_hashObj->update( (const Botan::byte*)a.data(), a.size() );
    }

    void final( QSecureArray *out)
    {
	out->resize( m_hashObj->OUTPUT_LENGTH );
	m_hashObj->final( (Botan::byte *)out->data() );
    }

protected:
    Botan::HMAC *m_hashObj;
};


//-----------------------------------------------------------
class BotanPBKDFContext: public QCA::KDFContext
{
public:
    BotanPBKDFContext(QString kdfName, QCA::Provider *p, const QString &type) : QCA::KDFContext(p, type)
    {
	m_s2k = Botan::get_s2k(kdfName.toStdString());
    }

    ~BotanPBKDFContext()
    {
	delete m_s2k;
    }

    Context *clone() const
    {
	return new BotanPBKDFContext( *this );
    }
    
    QCA::SymmetricKey makeKey(const QSecureArray &secret, const QCA::InitializationVector &salt,
			      unsigned int keyLength, unsigned int iterationCount)
    {
	m_s2k->set_iterations(iterationCount);
	m_s2k->change_salt((const Botan::byte*)salt.data(), salt.size());
	std::string secretString(secret.data(), secret.size() );
	Botan::OctetString key = m_s2k->derive_key(keyLength, secretString);
	QSecureArray retval(QByteArray((const char*)key.begin(), key.length()));
	return QCA::SymmetricKey(retval);
    }

protected:
    Botan::S2K* m_s2k;
};


//-----------------------------------------------------------
class BotanCipherContext : public QCA::CipherContext
{
public:
    BotanCipherContext(QString algo, QString mode, QString padding, QCA::Provider *p, const QString &type) : QCA::CipherContext(p, type)
    {
	m_algoName = algo.toStdString();
	m_algoMode = mode.toStdString();
	m_algoPadding = padding.toStdString();
    }

    void setup(QCA::Direction dir,
               const QCA::SymmetricKey &key,
               const QCA::InitializationVector &iv)
    {
	try {
	m_dir = dir;
	Botan::SymmetricKey keyCopy((Botan::byte*)key.data(), key.size());
	
	if (iv.size() == 0) {
	    if (QCA::Encode == dir) {
		m_crypter = new Botan::Pipe(Botan::get_cipher(m_algoName+"/"+m_algoMode+"/"+m_algoPadding,
							      keyCopy, Botan::ENCRYPTION));
	    }
	    else {
		m_crypter = new Botan::Pipe(Botan::get_cipher(m_algoName+"/"+m_algoMode+"/"+m_algoPadding,
							      keyCopy, Botan::DECRYPTION));
	    }
	} else {
	    Botan::InitializationVector ivCopy((Botan::byte*)iv.data(), iv.size());
	    if (QCA::Encode == dir) {
		m_crypter = new Botan::Pipe(Botan::get_cipher(m_algoName+"/"+m_algoMode+"/"+m_algoPadding,
							      keyCopy, ivCopy, Botan::ENCRYPTION));
	    }
	    else {
		m_crypter = new Botan::Pipe(Botan::get_cipher(m_algoName+"/"+m_algoMode+"/"+m_algoPadding,
							      keyCopy, ivCopy, Botan::DECRYPTION));
	    }
	}
	m_crypter->start_msg();
	} catch (Botan::Exception& e) {
	    std::cout << "caught: " << e.what() << std::endl;
	}
    }

    Context *clone() const
    {
	return new BotanCipherContext( *this );
    }

    unsigned int blockSize() const
    {
	return Botan::block_size_of(m_algoName);
    }

    bool update(const QSecureArray &in, QSecureArray *out)
    {
	QSecureArray result( in.size() + blockSize() );
	m_crypter->write((Botan::byte*)in.data(), in.size());
	int bytes_read = m_crypter->read((Botan::byte*)result.data(), result.size());
	result.resize(bytes_read);
        *out = result;
        return true;
    }

    bool final(QSecureArray *out)
    {
	QSecureArray result( 2 * blockSize() );
	m_crypter->end_msg();
	int bytes_read = m_crypter->read((Botan::byte*)result.data(), result.size());
	result.resize(bytes_read);
        *out = result;
        return true;
    }

    QCA::KeyLength keyLength() const
    {
	return QCA::KeyLength( Botan::min_keylength_of(m_algoName),
			       Botan::max_keylength_of(m_algoName),
			       Botan::keylength_multiple_of(m_algoName) );

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



//==========================================================
class botanProvider : public QCA::Provider
{
public:
    void init()
    { 
	m_init = new Botan::LibraryInitializer;
    }

    ~botanProvider()
    {
	// We should be cleaning up there, but
	// this causes the unit tests to segfault
	// delete m_init;
    }

    QString name() const
    {
	return "qca-botan";
    }
    
    QStringList features() const
    {
	QStringList list;
	list += "random";
	list += "md2";
	list += "md4";
	list += "md5";
	list += "sha1";
	list += "sha256";
	list += "sha384";
	list += "sha512";
	list += "ripemd160";
	list += "hmac(md5)";
	list += "hmac(sha1)";
	list += "hmac(sha256)";
	list += "hmac(sha384)";
	list += "hmac(sha512)";
	list += "hmac(ripemd160)";
	list += "pbkdf1(sha1)";
	list += "pbkdf1(md2)";
	list += "pbkdf2(sha1)";
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
	return list;
    }
    
    Context *createContext(const QString &type)
    {
	if ( type == "random" )
	    return new botanRandomContext( this );
	else if ( type == "md2" )
	    return new BotanHashContext( QString("MD2"), this, type );
	else if ( type == "md4" )
	    return new BotanHashContext( QString("MD4"), this, type );
	else if ( type == "md5" )
	    return new BotanHashContext( QString("MD5"), this, type );
	else if ( type == "sha1" )
	    return new BotanHashContext( QString("SHA-1"), this, type );
	else if ( type == "sha256" )
	    return new BotanHashContext( QString("SHA-256"), this, type );
	else if ( type == "sha384" )
	    return new BotanHashContext( QString("SHA-384"), this, type );
	else if ( type == "sha512" )
	    return new BotanHashContext( QString("SHA-512"), this, type );
	else if ( type == "ripemd160" )
	    return new BotanHashContext( QString("RIPEMD-160"), this, type );
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
	else if ( type == "pbkdf1(sha1)" )
	    return new BotanPBKDFContext( QString("PBKDF1(SHA-1)"), this, type );
	else if ( type == "pbkdf1(md2)" )
	    return new BotanPBKDFContext( QString("PBKDF1(MD2)"), this, type );
	else if ( type == "pbkdf2(sha1)" )
	    return new BotanPBKDFContext( QString("PBKDF2(SHA-1)"), this, type );
	else if ( type == "aes128-ecb" )
	    return new BotanCipherContext( QString("AES-128"), QString("ECB"), QString("NoPadding"), this, type );
	else if ( type == "aes128-cbc" )
	    return new BotanCipherContext( QString("AES-128"), QString("CBC"), QString("NoPadding"), this, type );
	else if ( type == "aes128-cfb" )
	    return new BotanCipherContext( QString("AES-128"), QString("CFB"), QString("NoPadding"), this, type );
	else if ( type == "aes128-ofb" )
	    return new BotanCipherContext( QString("AES-128"), QString("OFB"), QString("NoPadding"), this, type );
	else if ( type == "aes192-ecb" )
	    return new BotanCipherContext( QString("AES-192"), QString("ECB"), QString("NoPadding"), this, type );
	else if ( type == "aes192-cbc" )
	    return new BotanCipherContext( QString("AES-192"), QString("CBC"), QString("NoPadding"), this, type );
	else if ( type == "aes192-cfb" )
	    return new BotanCipherContext( QString("AES-192"), QString("CFB"), QString("NoPadding"), this, type );
	else if ( type == "aes192-ofb" )
	    return new BotanCipherContext( QString("AES-192"), QString("OFB"), QString("NoPadding"), this, type );
	else if ( type == "aes256-ecb" )
	    return new BotanCipherContext( QString("AES-256"), QString("ECB"), QString("NoPadding"), this, type );
	else if ( type == "aes256-cbc" )
	    return new BotanCipherContext( QString("AES-256"), QString("CBC"), QString("NoPadding"), this, type );
	else if ( type == "aes256-cfb" )
	    return new BotanCipherContext( QString("AES-256"), QString("CFB"), QString("NoPadding"), this, type );
	else if ( type == "aes256-ofb" )
	    return new BotanCipherContext( QString("AES-256"), QString("OFB"), QString("NoPadding"), this, type );
	else if ( type == "blowfish-ecb" )
	    return new BotanCipherContext( QString("Blowfish"), QString("ECB"), QString("NoPadding"), this, type );
	else if ( type == "blowfish-cbc" )
	    return new BotanCipherContext( QString("Blowfish"), QString("CBC"), QString("NoPadding"), this, type );
	else if ( type == "blowfish-cbc-pkcs7" )
	    return new BotanCipherContext( QString("Blowfish"), QString("CBC"), QString("PKCS7"), this, type );
	else if ( type == "blowfish-cfb" )
	    return new BotanCipherContext( QString("Blowfish"), QString("CFB"), QString("NoPadding"), this, type );
	else if ( type == "blowfish-ofb" )
	    return new BotanCipherContext( QString("Blowfish"), QString("OFB"), QString("NoPadding"), this, type );
	else if ( type == "des-ecb" )
	    return new BotanCipherContext( QString("DES"), QString("ECB"), QString("NoPadding"), this, type );
	else if ( type == "des-ecb-pkcs7" )
	    return new BotanCipherContext( QString("DES"), QString("ECB"), QString("PKCS7"), this, type );
	else if ( type == "des-cbc" )
	    return new BotanCipherContext( QString("DES"), QString("CBC"), QString("NoPadding"), this, type );
	else if ( type == "des-cbc-pkcs7" )
	    return new BotanCipherContext( QString("DES"), QString("CBC"), QString("PKCS7"), this, type );
	else if ( type == "des-cfb" )
	    return new BotanCipherContext( QString("DES"), QString("CFB"), QString("NoPadding"), this, type );
	else if ( type == "des-ofb" )
	    return new BotanCipherContext( QString("DES"), QString("OFB"), QString("NoPadding"), this, type );
	else if ( type == "tripledes-ecb" )
	    return new BotanCipherContext( QString("TripleDES"), QString("ECB"), QString("NoPadding"), this, type );
	else
	    return 0;
    }
private:
    Botan::LibraryInitializer *m_init;

};

class botanPlugin : public QCAPlugin
{
	Q_OBJECT
	Q_INTERFACES(QCAPlugin)
public:
	virtual QCA::Provider *createProvider() { return new botanProvider; }
};

#include "qca-botan.moc"

Q_EXPORT_PLUGIN2(qca-botan, botanPlugin);


