/*
 * Copyright (C) 2004  Justin Karneges
 * Copyright (C) 2004  Brad Hards <bradh@frogmouth.net>
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
#include <QtCore>
#include <QtCrypto>

#include <qstringlist.h>
#include <gcrypt.h>
#include <iostream>

namespace gcryptQCAPlugin {

void check_error( gcry_error_t err )
{
    // we ignore the case where it is not an error, and
    // we also don't flag weak keys.
    if ( ( GPG_ERR_NO_ERROR != err ) && ( GPG_ERR_WEAK_KEY  != gpg_err_code(err) ) ) {
	std::cout << "Failure: " ;
		std::cout << gcry_strsource(err) << "/";
		std::cout << gcry_strerror(err) << std::endl;
    }
}

class gcryHashContext : public QCA::HashContext
{
public:
    gcryHashContext(QCA::Provider *p, const QString &type) : QCA::HashContext(p, type) {};

    void clear()
    {
	gcry_md_reset( context );
    }
    
    void update(const QSecureArray &a)
    {
	gcry_md_write( context, a.data(), a.size() );
    }
    
    QSecureArray final()
    {
	unsigned char *md;
	QSecureArray a( gcry_md_get_algo_dlen( hashAlgorithm ) );
	md = gcry_md_read( context, hashAlgorithm );
	memcpy( a.data(), md, a.size() );
	return a;
    }
    
protected:
    gcry_md_hd_t context;
    gcry_error_t err;
    int hashAlgorithm;
};	

class SHA1Context : public gcryHashContext
{
public:
	SHA1Context(QCA::Provider *p) : gcryHashContext(p, "sha1")
	{
		gcry_check_version("GCRYPT_VERSION");
		hashAlgorithm = GCRY_MD_SHA1;
		err =  gcry_md_open( &context, hashAlgorithm, 0 );
		if ( GPG_ERR_NO_ERROR != err ) {
			std::cout << "Failure: " ;
			std::cout << gcry_strsource(err) << "/";
			std::cout << gcry_strerror(err) << std::endl;
		}
	}

	~SHA1Context()
	{
		gcry_md_close( context );
	}

	Context *clone() const
	{
		return new SHA1Context(*this);
	}
};

class MD4Context : public gcryHashContext
{
public:
	MD4Context(QCA::Provider *p) : gcryHashContext(p, "md4")
	{
		gcry_check_version("GCRYPT_VERSION");
		hashAlgorithm = GCRY_MD_MD4;
		err =  gcry_md_open( &context, hashAlgorithm, 0 );
		if ( GPG_ERR_NO_ERROR != err ) {
			std::cout << "Failure: " ;
			std::cout << gcry_strsource(err) << "/";
			std::cout << gcry_strerror(err) << std::endl;
		}
	}

	~MD4Context()
	{
		gcry_md_close( context );
	}

	Context *clone() const
	{
		return new MD4Context(*this);
	}
};


class MD5Context : public gcryHashContext
{
public:
	MD5Context(QCA::Provider *p) : gcryHashContext(p, "md5")
	{
		gcry_check_version("GCRYPT_VERSION");
		hashAlgorithm = GCRY_MD_MD5;
		err =  gcry_md_open( &context, hashAlgorithm, 0 );
		if ( GPG_ERR_NO_ERROR != err ) {
			std::cout << "Failure: " ;
			std::cout << gcry_strsource(err) << "/";
			std::cout << gcry_strerror(err) << std::endl;
		}
	}

	~MD5Context()
	{
		gcry_md_close( context );
	}

	Context *clone() const
	{
		return new MD5Context(*this);
	}
};

class RIPEMD160Context : public gcryHashContext
{
public:
	RIPEMD160Context(QCA::Provider *p) : gcryHashContext(p, "ripemd160")
	{
		gcry_check_version("GCRYPT_VERSION");
		hashAlgorithm = GCRY_MD_RMD160;
		err =  gcry_md_open( &context, hashAlgorithm, 0 );
		if ( GPG_ERR_NO_ERROR != err ) {
			std::cout << "Failure: " ;
			std::cout << gcry_strsource(err) << "/";
			std::cout << gcry_strerror(err) << std::endl;
		}
	}

	~RIPEMD160Context()
	{
		gcry_md_close( context );
	}

	Context *clone() const
	{
		return new RIPEMD160Context(*this);
	}
};


class SHA256Context : public gcryHashContext
{
public:
    SHA256Context(QCA::Provider *p) : gcryHashContext(p, "sha256")
    {
	gcry_check_version("GCRYPT_VERSION");
	hashAlgorithm = GCRY_MD_SHA256;
	err =  gcry_md_open( &context, hashAlgorithm, 0 );
	if ( GPG_ERR_NO_ERROR != err ) {
	    std::cout << "Failure: " ;
	    std::cout << gcry_strsource(err) << "/";
	    std::cout << gcry_strerror(err) << std::endl;
	}
    }
	
    ~SHA256Context()
    {
	gcry_md_close( context );
    }

    Context *clone() const
    {
	return new SHA256Context(*this);
    }
};

class SHA384Context : public gcryHashContext
{
public:
	SHA384Context(QCA::Provider *p) : gcryHashContext(p, "sha384")
	{
		gcry_check_version("GCRYPT_VERSION");
		hashAlgorithm = GCRY_MD_SHA384;
		err =  gcry_md_open( &context, hashAlgorithm, 0 );
		if ( GPG_ERR_NO_ERROR != err ) {
			std::cout << "Failure: " ;
			std::cout << gcry_strsource(err) << "/";
			std::cout << gcry_strerror(err) << std::endl;
		}
	}

	~SHA384Context()
	{
		gcry_md_close( context );
	}

	Context *clone() const
	{
		return new SHA384Context(*this);
	}
};




class SHA512Context : public gcryHashContext
{
public:
	SHA512Context(QCA::Provider *p) : gcryHashContext(p, "sha512")
	{
		gcry_check_version("GCRYPT_VERSION");
		hashAlgorithm = GCRY_MD_SHA512;
		err =  gcry_md_open( &context, hashAlgorithm, 0 );
		if ( GPG_ERR_NO_ERROR != err ) {
			std::cout << "Failure: " ;
			std::cout << gcry_strsource(err) << "/";
			std::cout << gcry_strerror(err) << std::endl;
		}
	}

	~SHA512Context()
	{
		gcry_md_close( context );
	}

	Context *clone() const
	{
		return new SHA512Context(*this);
	}
};

class gcryCipherContext : public QCA::CipherContext
{
public:
    gcryCipherContext(int algorithm, int mode, bool pad, QCA::Provider *p, const QString &type) : QCA::CipherContext(p, type)
    {
	gcry_check_version("GCRYPT_VERSION");
	m_cryptoAlgorithm = algorithm;
 	m_mode = mode;
	m_pad = pad;
    }

    void setup(QCA::Direction dir,
	       const QCA::SymmetricKey &key,
	       const QCA::InitializationVector &iv)
    {
	m_direction = dir;
	err =  gcry_cipher_open( &context, m_cryptoAlgorithm, m_mode, 0 );
	check_error( err );
	err = gcry_cipher_setkey( context, key.data(), key.size() );
	check_error( err );
	err = gcry_cipher_setiv( context, iv.data(), iv.size() );
	check_error( err ); 
    }

    Context *clone() const
    {
      return new gcryCipherContext( *this );
    }

    unsigned int blockSize() const
    {
	unsigned int blockSize;
	gcry_cipher_algo_info( m_cryptoAlgorithm, GCRYCTL_GET_BLKLEN, 0, (size_t*)&blockSize );
	return blockSize;
    }
    
    bool update(const QSecureArray &in, QSecureArray *out)
    {
	QSecureArray result( in.size() );
	if (QCA::Encode == m_direction) {
	    err = gcry_cipher_encrypt( context, (unsigned char*)result.data(), result.size(), (unsigned char*)in.data(), in.size() );
	} else {
	    err = gcry_cipher_decrypt( context, (unsigned char*)result.data(), result.size(), (unsigned char*)in.data(), in.size() );
	}
	check_error(err );
	result.resize( in.size() );
	*out = result;
	return true;
    }
    
    bool final(QSecureArray *out)
    {
	QSecureArray result;
	if (m_pad) {
	    result.resize( blockSize() );
	    if (QCA::Encode == m_direction) {
		err = gcry_cipher_encrypt( context, (unsigned char*)result.data(), result.size(), NULL, 0 );
	    } else {
		err = gcry_cipher_decrypt( context, (unsigned char*)result.data(), result.size(), NULL, 0 );
	    }
	    check_error(err );
	} else {
	    // just return null
	}
	*out = result;
	return true;
    }

    QCA::KeyLength keyLength() const
    {
    switch (m_cryptoAlgorithm)
	{
	case GCRY_CIPHER_DES:
	    return QCA::KeyLength( 8, 8, 1);
	case GCRY_CIPHER_AES128:
	    return QCA::KeyLength( 16, 16, 1);
	case GCRY_CIPHER_AES192:
	case GCRY_CIPHER_3DES:
	    	return QCA::KeyLength( 24, 24, 1);
	case GCRY_CIPHER_AES256:
	    	return QCA::KeyLength( 32, 32, 1);
	case GCRY_CIPHER_BLOWFISH:
	    // Don't know - TODO
	    return QCA::KeyLength( 1, 32, 1);
	default:
	    return QCA::KeyLength( 0, 1, 1);
	}
    }


protected:
    gcry_cipher_hd_t context;
    gcry_error_t err;
    int m_cryptoAlgorithm;
    QCA::Direction m_direction;
    int m_mode;
    bool m_pad;
};

}

using namespace gcryptQCAPlugin;

class gcryptProvider : public QCA::Provider
{
public:
    void init()
    {
    }
    
    QString name() const
    {
	return "qca-gcrypt";
    }

    QStringList features() const
    {
	QStringList list;
	list += "sha1";
	list += "md4";
	list += "md5";
	list += "ripemd160";
	list += "sha256";
	list += "sha384";
	list += "sha512";
	list += "aes128-ecb";
	list += "aes128-cfb";
	list += "aes128-cbc";
	list += "aes192-ecb";
	list += "aes192-cfb";
	list += "aes192-cbc";
	list += "aes256-ecb";
	list += "aes256-cfb";
	list += "aes256-cbc";
	list += "blowfish-ecb";
	list += "tripledes-ecb";
	list += "des-ecb";
	return list;
    }

    Context *createContext(const QString &type)
    {
	//std::cout << "type: " << qPrintable(type) << std::endl; 
	if ( type == "sha1" )
	    return new SHA1Context( this );
	else if ( type == "md4" )
	    return new MD4Context( this );
	else if ( type == "md5" )
	    return new MD5Context( this );
	else if ( type == "ripemd160" )
	    return new RIPEMD160Context( this );
	else if ( type == "sha256" )
	    return new SHA256Context( this );
	else if ( type == "sha384" )
	    return new SHA384Context( this );
	else if ( type == "sha512" )
	    return new SHA512Context( this );
	else if ( type == "aes128-ecb" )
	    return new gcryCipherContext( GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, false, this, type );
	else if ( type == "aes128-cfb" )
	    return new gcryCipherContext( GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CFB, false, this, type );
	else if ( type == "aes128-cbc" )
	    return new gcryCipherContext( GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, false, this, type );
	else if ( type == "aes192-ecb" )
	    return new gcryCipherContext( GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB, false, this, type );
	else if ( type == "aes192-cfb" )
	    return new gcryCipherContext( GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CFB, false, this, type );
	else if ( type == "aes192-cbc" )
	    return new gcryCipherContext( GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC, false, this, type );
	else if ( type == "aes256-ecb" )
	    return new gcryCipherContext( GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, false, this, type );
	else if ( type == "aes256-cfb" )
	    return new gcryCipherContext( GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, false, this, type );
	else if ( type == "aes256-cbc" )
	    return new gcryCipherContext( GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, false, this, type );
	else if ( type == "blowfish-ecb" )
	    return new gcryCipherContext( GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB, false, this, type );
	else if ( type == "tripledes-ecb" )
	    return new gcryCipherContext( GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_ECB, false, this, type );
	else if ( type == "des-ecb" )
	    return new gcryCipherContext( GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, false, this, type );
	else
	    return 0;
    }
};

class gcryptPlugin : public QCAPlugin
{
    Q_OBJECT
	public:
    virtual int version() const { return QCA_PLUGIN_VERSION; }
    virtual QCA::Provider *createProvider() { return new gcryptProvider; }
};

#include "qca-gcrypt.moc"

Q_EXPORT_PLUGIN(gcryptPlugin);

