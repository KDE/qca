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
#include <openssl/evp.h>
#include <openssl/hmac.h>

class opensslHashContext : public QCA::HashContext
{
public:
    opensslHashContext(QCA::Provider *p, const QString &type) : QCA::HashContext(p, type) {};

    void clear()
    {
	EVP_DigestInit( &m_context, m_algorithm );
    }
    
    void update(const QSecureArray &a)
    {
	EVP_DigestUpdate( &m_context, (unsigned char*)a.data(), a.size() );
    }
    
    QSecureArray final()
    {
	QSecureArray a( EVP_MD_size( m_algorithm ) );
	EVP_DigestFinal( &m_context, (unsigned char*)a.data(), 0 );
	return a;
    }
    
protected:
    const EVP_MD *m_algorithm;
    EVP_MD_CTX m_context;
};	

class SHA1Context : public opensslHashContext
{
public:
    SHA1Context(QCA::Provider *p) : opensslHashContext(p, "sha1")
    {
	m_algorithm = EVP_get_digestbyname("sha1");
	clear();
    }

    ~SHA1Context()
    {
    }

    Context *clone() const
    {
	return new SHA1Context(*this);
    }
};


class SHA0Context : public opensslHashContext
{
public:
    SHA0Context(QCA::Provider *p) : opensslHashContext(p, "sha")
    {
	m_algorithm = EVP_sha();
	clear();
    }

    ~SHA0Context()
    {
    }

    Context *clone() const
    {
	return new SHA0Context(*this);
    }
};


class MD2Context : public opensslHashContext
{
public:
    MD2Context(QCA::Provider *p) : opensslHashContext(p, "md2")
    {
	m_algorithm = EVP_md2();
	clear();
    }

    ~MD2Context()
    {
    }

    Context *clone() const
    {
	return new MD2Context(*this);
    }
};


class MD4Context : public opensslHashContext
{
public:
    MD4Context(QCA::Provider *p) : opensslHashContext(p, "md4")
    {
	m_algorithm = EVP_md4();
	clear();
    }

    ~MD4Context()
    {
    }

    Context *clone() const
    {
	return new MD4Context(*this);
    }
};


class MD5Context : public opensslHashContext
{
public:
    MD5Context(QCA::Provider *p) : opensslHashContext(p, "md5")
    {
	m_algorithm = EVP_md5();
	clear();
    }

    ~MD5Context()
    {
    }

    Context *clone() const
    {
	return new MD5Context(*this);
    }
};


class RIPEMD160Context : public opensslHashContext
{
public:
    RIPEMD160Context(QCA::Provider *p) : opensslHashContext(p, "ripemd160")
    {
	m_algorithm = EVP_ripemd160();
	clear();
    }

    ~RIPEMD160Context()
    {
    }

    Context *clone() const
    {
	return new RIPEMD160Context(*this);
    }
};


class opensslHMACContext : public QCA::MACContext
{
public:
    opensslHMACContext(QCA::Provider *p, const QString &type) : QCA::MACContext(p, type) {};

    void setup(const QCA::SymmetricKey &key)
    {
	HMAC_Init_ex( &m_context, key.data(), key.size(), m_algorithm, 0 );
    }
    
    QCA::KeyLength keyLength() const
    {
	return anyKeyLength();
    }

    void update(const QSecureArray &a)
    {
	HMAC_Update( &m_context, (unsigned char *)a.data(), a.size() );
    }
    
    void final( QSecureArray *out)
    {
	out->resize( EVP_MD_size( m_algorithm ) );
	HMAC_Final(&m_context, (unsigned char *)out->data(), 0 );
	HMAC_CTX_cleanup(&m_context);
    }

protected:
    HMAC_CTX m_context;
    const EVP_MD *m_algorithm;
};

class HMACMD5Context : public opensslHMACContext
{
public:
    HMACMD5Context(QCA::Provider *p) : opensslHMACContext( p, "hmac(md5)" )
    {
	m_algorithm = EVP_md5();
	HMAC_CTX_init( &m_context );
    }
	
    Context *clone() const
    {
	return new HMACMD5Context(*this);
    }
    
};

class HMACSHA1Context : public opensslHMACContext
{
public:
    HMACSHA1Context(QCA::Provider *p) : opensslHMACContext( p, "hmac(sha1)" )
    {
	m_algorithm = EVP_sha1();
	HMAC_CTX_init( &m_context );
    }
	
    Context *clone() const
    {
	return new HMACSHA1Context(*this);
    }
    
};

class HMACRIPEMD160Context : public opensslHMACContext
{
public:
    HMACRIPEMD160Context(QCA::Provider *p) : opensslHMACContext( p, "hmac(ripemd160)" )
    {
	m_algorithm = EVP_ripemd160();
	HMAC_CTX_init( &m_context );
    }
	
    Context *clone() const
    {
	return new HMACRIPEMD160Context(*this);
    }
    
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
		list += "sha1";
		list += "sha0";
		list += "ripemd160";
		list += "md2";
		list += "md4";
		list += "md5";
		list += "hmac(md5)";
		list += "hmac(sha1)";
		list += "hmac(ripemd160)";
		return list;
	}

	Context *createContext(const QString &type)
	{
	    OpenSSL_add_all_digests();
	    if ( type == "sha1" )
		return new SHA1Context( this );
	    else if ( type == "sha0" )
		return new SHA0Context( this );
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

class opensslPlugin : public QCAPlugin
{
	Q_OBJECT
public:
	virtual int version() const { return QCA_PLUGIN_VERSION; }
	virtual QCA::Provider *createProvider() { return new opensslProvider; }
};

#include "qca-openssl.moc"

Q_EXPORT_PLUGIN(opensslPlugin);

