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
#include "qcaprovider.h"
#include <qstringlist.h>
#include <gcrypt.h>
#include <iostream>

void check_error( gcry_error_t err )
{
    if ( GPG_ERR_NO_ERROR != err ) {
	std::cout << "Failure: " ;
		std::cout << gcry_strsource(err) << "/";
		std::cout << gcry_strerror(err) << std::endl;
    }
}

class SHA1Context : public QCA::HashContext
{
public:
	SHA1Context(QCA::Provider *p) : HashContext(p, "sha1")
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


class SHA256Context : public QCA::HashContext
{
public:
	SHA256Context(QCA::Provider *p) : HashContext(p, "sha256")
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

class SHA384Context : public QCA::HashContext
{
public:
	SHA384Context(QCA::Provider *p) : HashContext(p, "sha384")
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




class SHA512Context : public QCA::HashContext
{
public:
	SHA512Context(QCA::Provider *p) : HashContext(p, "sha512")
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

int gcry_mode( QCA::CipherContext::Mode mode )
{
    int retmode;
    switch (mode)
    {
    case QCA::CipherContext::ECB :
	retmode = GCRY_CIPHER_MODE_ECB;
	break;
    case QCA::CipherContext::CBC :
	retmode = GCRY_CIPHER_MODE_CBC;
	break;
    case QCA::CipherContext::CFB :
	retmode = GCRY_CIPHER_MODE_CFB;
	break;
    default:
	retmode = GCRY_CIPHER_MODE_NONE;
    }
    return retmode;
}

class AES128Context : public QCA::CipherContext
{
public:
    AES128Context(QCA::Provider *p) : CipherContext( p, "aes128" )
    {
	gcry_check_version("GCRYPT_VERSION");
	cryptoAlgorithm = GCRY_CIPHER_AES128;
    }
	
    Context *clone() const
    {
	return new AES128Context( *this );
    }
    

    void setup(const QCA::SymmetricKey &key,
	       QCA::CipherContext::Mode m,
	       QCA::Direction dir,
	       const QCA::InitializationVector &iv,
	       bool pad)
    {
	m_direction = dir;
	err =  gcry_cipher_open( &context, cryptoAlgorithm, gcry_mode(m), 0 );
	check_error( err );
	err = gcry_cipher_setkey( context, key.data(), key.size() );
	check_error( err );
	err = gcry_cipher_setiv( context, iv.data(), iv.size() );
	check_error( err ); 
    }

    QCA::KeyLength keyLength() const
    {
	// Must be 128 bits
	return QCA::KeyLength( 16, 16, 1);
    }
    
    int blockSize() const
    {
	// TODO: this needs more work!
	return 32;
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
	runningResult.append( result );
	return true;
    }
    
    bool final(QSecureArray *out)
    {
	*out = runningResult.copy();
	return true;
    }

protected:
    gcry_cipher_hd_t context;
    gcry_error_t err;
    int cryptoAlgorithm;
    QCA::Direction m_direction;
    QSecureArray runningResult;
};


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
		list += "sha256";
		list += "sha384";
		list += "sha512";
		list += "aes128";
		return list;
	}

	Context *createContext(const QString &type)
	{
		if ( type == "sha1" )
			return new SHA1Context( this );
		else if ( type == "sha256" )
			return new SHA256Context( this );
		else if ( type == "sha384" )
			return new SHA384Context( this );
		else if ( type == "sha512" )
			return new SHA512Context( this );
		else if ( type == "aes128" )
			return new AES128Context( this );
		else
			return 0;
	}
};

QCA_EXPORT_PLUGIN(gcryptProvider);
