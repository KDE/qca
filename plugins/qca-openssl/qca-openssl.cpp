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
#include <openssl/sha.h>
#include <openssl/md2.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/hmac.h>

class MD2Context : public QCA::HashContext
{
public:
	MD2Context(QCA::Provider *p) : HashContext(p, "md2")
	{
		clear();
	}

	Context *clone() const
	{
		return new MD2Context(*this);
	}

	void clear()
	{
		MD2_Init(&c);
	}

	void update(const QSecureArray &a)
	{
		MD2_Update(&c, (unsigned char *)a.data(), a.size());
	}

	QSecureArray final()
	{
		QSecureArray a(MD2_DIGEST_LENGTH);
		MD2_Final((unsigned char *)a.data(), &c);
		return a;
	}

protected:
	MD2_CTX c;
};

class MD4Context : public QCA::HashContext
{
public:
	MD4Context(QCA::Provider *p) : HashContext(p, "md4")
	{
		clear();
	}

	Context *clone() const
	{
		return new MD4Context(*this);
	}

	void clear()
	{
		MD4_Init(&c);
	}

	void update(const QSecureArray &a)
	{
		MD4_Update(&c, (unsigned char *)a.data(), a.size());
	}

	QSecureArray final()
	{
		QSecureArray a(MD4_DIGEST_LENGTH);
		MD4_Final((unsigned char *)a.data(), &c);
		return a;
	}

protected:
	MD4_CTX c;
};

class MD5Context : public QCA::HashContext
{
public:
	MD5Context(QCA::Provider *p) : HashContext(p, "md5")
	{
		clear();
	}

	Context *clone() const
	{
		return new MD5Context(*this);
	}

	void clear()
	{
		MD5_Init(&c);
	}

	void update(const QSecureArray &a)
	{
		MD5_Update(&c, (unsigned char *)a.data(), a.size());
	}

	QSecureArray final()
	{
		QSecureArray a(MD5_DIGEST_LENGTH);
		MD5_Final((unsigned char *)a.data(), &c);
		return a;
	}

protected:
	MD5_CTX c;
};

class SHA0Context : public QCA::HashContext
{
public:
	SHA0Context(QCA::Provider *p) : HashContext(p, "sha0")
	{
		clear();
	}

	Context *clone() const
	{
		return new SHA0Context(*this);
	}

	void clear()
	{
		SHA_Init(&c);
	}

	void update(const QSecureArray &a)
	{
		SHA_Update(&c, (unsigned char *)a.data(), a.size());
	}

	QSecureArray final()
	{
		QSecureArray a(SHA_DIGEST_LENGTH);
		SHA_Final((unsigned char *)a.data(), &c);
		return a;
	}

protected:
	SHA_CTX c;
};

class SHA1Context : public QCA::HashContext
{
public:
	SHA1Context(QCA::Provider *p) : HashContext(p, "sha1")
	{
		clear();
	}

	Context *clone() const
	{
		return new SHA1Context(*this);
	}

	void clear()
	{
		SHA1_Init(&c);
	}

	void update(const QSecureArray &a)
	{
		SHA1_Update(&c, (unsigned char *)a.data(), a.size());
	}

	QSecureArray final()
	{
		QSecureArray a(SHA_DIGEST_LENGTH);
		SHA1_Final((unsigned char *)a.data(), &c);
		return a;
	}

protected:
	SHA_CTX c;
};

class RIPEMD160Context : public QCA::HashContext
{
public:
	RIPEMD160Context(QCA::Provider *p) : HashContext(p, "ripemd160")
	{
		clear();
	}

	Context *clone() const
	{
		return new RIPEMD160Context(*this);
	}

	void clear()
	{
		RIPEMD160_Init(&c);
	}

	void update(const QSecureArray &a)
	{
		RIPEMD160_Update(&c, (unsigned char *)a.data(), a.size());
	}

	QSecureArray final()
	{
		QSecureArray result(RIPEMD160_DIGEST_LENGTH);
		RIPEMD160_Final((unsigned char *)result.data(), &c);
		return result;
	}

protected:
	RIPEMD160_CTX c;
};

class HMACMD5Context : public QCA::MACContext
{
public:
	HMACMD5Context(QCA::Provider *p) : MACContext( p, "hmac(md5)" )
	{
		HMAC_CTX_init( &c );
	}

	Context *clone() const
	{
		return new HMACMD5Context(*this);
	}

	void setup(const QCA::SymmetricKey &key)
	{
		HMAC_Init_ex( &c, key.data(), key.size(), EVP_md5(), 0 );
	}

	QCA::KeyLength keyLength() const
	{
		return anyKeyLength();
	}

	void update(const QSecureArray &a)
	{
		HMAC_Update( &c, (unsigned char *)a.data(), a.size() );
	}

	void final( QSecureArray *out)
	{
		unsigned int outSize;
		out->resize( MD5_DIGEST_LENGTH );
		HMAC_Final(&c, (unsigned char *)out->data(), &(outSize) );
		HMAC_CTX_cleanup(&c);
	}

protected:
	HMAC_CTX c;
};


class HMACSHA1Context : public QCA::MACContext
{
public:
	HMACSHA1Context(QCA::Provider *p) : MACContext( p, "hmac(sha1)" )
	{
		HMAC_CTX_init( &c );
	}

	Context *clone() const
	{
		return new HMACSHA1Context(*this);
	}

	void setup(const QCA::SymmetricKey &key)
	{
		HMAC_Init_ex( &c, key.data(), key.size(), EVP_sha1(), 0 );
	}

	QCA::KeyLength keyLength() const
	{
		return anyKeyLength();
	}

	void update(const QSecureArray &a)
	{
		HMAC_Update( &c, (unsigned char *)a.data(), a.size() );
	}

	void final( QSecureArray *out)
	{
		unsigned int outSize;
		out->resize( SHA_DIGEST_LENGTH );
		HMAC_Final(&c, (unsigned char *)out->data(), &(outSize) );
		HMAC_CTX_cleanup(&c);
	}

protected:
	HMAC_CTX c;
};

class HMACRIPEMD160Context : public QCA::MACContext
{
public:
	HMACRIPEMD160Context(QCA::Provider *p) : MACContext( p, "hmac(ripemd160)" )
	{
		HMAC_CTX_init( &c );
	}

	Context *clone() const
	{
		return new HMACRIPEMD160Context(*this);
	}

	void setup(const QCA::SymmetricKey &key)
	{
		HMAC_Init_ex( &c, key.data(), key.size(), EVP_ripemd160(), 0 );
	}

	QCA::KeyLength keyLength() const
	{
		return anyKeyLength();
	}

	void update(const QSecureArray &a)
	{
		HMAC_Update( &c, (unsigned char *)a.data(), a.size() );
	}

	void final( QSecureArray *out)
	{
		unsigned int outSize;
		out->resize( RIPEMD160_DIGEST_LENGTH );
		HMAC_Final(&c, (unsigned char *)out->data(), &(outSize) );
		HMAC_CTX_cleanup(&c);
	}

protected:
	HMAC_CTX c;
};

class opensslProvider : public QCA::Provider
{
public:
	void init()
	{
	}

	QString name() const
	{
		return "qca-openssl";
	}

	QStringList features() const
	{
		QStringList list;
		list += "sha0";
		list += "sha1";
		list += "ripemd160";
		list += "md2";
		list += "md4";
		list += "md5";
		list += "hmac(md5)";
		list += "hmac(sha1)";
		list += "hmac(ripemd160)";
		list += "aes128";
		return list;
	}

	Context *createContext(const QString &type)
	{
		if ( type == "sha0" )
			return new SHA0Context( this );
		else if ( type == "sha1" )
			return new SHA1Context( this );
		else if ( type == "ripemd160" )
			return new RIPEMD160Context( this );
		else if ( type == "md2" )
			return new MD2Context( this );
		else if ( type == "md4" )
			return new MD4Context( this );
		else if ( type == "md5" )
			return new MD5Context( this );
		else if ( type == "hmac(md5)" )
			return new HMACMD5Context( this );
		else if ( type == "hmac(sha1)" )
			return new HMACSHA1Context( this );
		else if ( type == "hmac(ripemd160)" )
			return new HMACRIPEMD160Context( this );
		else
			return 0;
	}
};

QCA_EXPORT_PLUGIN(opensslProvider);
