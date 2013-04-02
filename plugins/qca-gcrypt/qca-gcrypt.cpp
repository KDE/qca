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

#include <qstringlist.h>
#include <gcrypt.h>
#include <iostream>

namespace gcryptQCAPlugin {

#include "pkcs5.c"

void check_error( const QString &label, gcry_error_t err )
{
    // we ignore the case where it is not an error, and
    // we also don't flag weak keys.
    if ( ( GPG_ERR_NO_ERROR != err ) && ( GPG_ERR_WEAK_KEY  != gpg_err_code(err) ) ) {
	std::cout << "Failure (" << qPrintable(label) << "): ";
		std::cout << gcry_strsource(err) << "/";
		std::cout << gcry_strerror(err) << std::endl;
    }
}

class gcryHashContext : public QCA::HashContext
{
public:
    gcryHashContext(int hashAlgorithm, QCA::Provider *p, const QString &type) : QCA::HashContext(p, type)
    {
	m_hashAlgorithm = hashAlgorithm;
	err =  gcry_md_open( &context, m_hashAlgorithm, 0 );
	if ( GPG_ERR_NO_ERROR != err ) {
	    std::cout << "Failure: " ;
	    std::cout << gcry_strsource(err) << "/";
	    std::cout << gcry_strerror(err) << std::endl;
	}
    }

    ~gcryHashContext()
    {
	gcry_md_close( context );
    }

    Context *clone() const
    {
	return new gcryHashContext(*this);
    }

    void clear()
    {
	gcry_md_reset( context );
    }

    void update(const QCA::MemoryRegion &a)
    {
	gcry_md_write( context, a.data(), a.size() );
    }

    QCA::MemoryRegion final()
    {
	unsigned char *md;
        QCA::SecureArray a( gcry_md_get_algo_dlen( m_hashAlgorithm ) );
	md = gcry_md_read( context, m_hashAlgorithm );
	memcpy( a.data(), md, a.size() );
	return a;
    }

protected:
    gcry_md_hd_t context;
    gcry_error_t err;
    int m_hashAlgorithm;
};

class gcryHMACContext : public QCA::MACContext
{
public:
    gcryHMACContext(int hashAlgorithm, QCA::Provider *p, const QString &type) : QCA::MACContext(p, type)
    {
        m_hashAlgorithm = hashAlgorithm;
        err =  gcry_md_open( &context, m_hashAlgorithm, GCRY_MD_FLAG_HMAC );
        if ( GPG_ERR_NO_ERROR != err ) {
            std::cout << "Failure: " ;
            std::cout << gcry_strsource(err) << "/";
            std::cout << gcry_strerror(err) << std::endl;
        }
    }

    ~gcryHMACContext()
    {
        gcry_md_close( context );
    }

    void setup(const QCA::SymmetricKey &key)
    {
        gcry_md_setkey( context, key.data(), key.size() );
    }

    Context *clone() const
    {
        return new gcryHMACContext(*this);
    }

    void clear()
    {
        gcry_md_reset( context );
    }

    QCA::KeyLength keyLength() const
    {
        return anyKeyLength();
    }

    void update(const QCA::MemoryRegion &a)
    {
        gcry_md_write( context, a.data(), a.size() );
    }

    void final( QCA::MemoryRegion *out)
    {
        QCA::SecureArray sa( gcry_md_get_algo_dlen( m_hashAlgorithm ), 0 );
        unsigned char *md;
        md = gcry_md_read( context, m_hashAlgorithm );
        memcpy( sa.data(), md, sa.size() );
        *out = sa;
    }

protected:
    gcry_md_hd_t context;
    gcry_error_t err;
    int m_hashAlgorithm;
};


class gcryCipherContext : public QCA::CipherContext
{
public:
    gcryCipherContext(int algorithm, int mode, bool pad, QCA::Provider *p, const QString &type) : QCA::CipherContext(p, type)
    {
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
	check_error( "gcry_cipher_open", err );
	if ( ( GCRY_CIPHER_3DES == m_cryptoAlgorithm ) && (key.size() == 16) ) {
	    // this is triple DES with two keys, and gcrypt wants three
	    QCA::SymmetricKey keyCopy(key);
            QCA::SecureArray thirdKey(key);
	    thirdKey.resize(8);
	    keyCopy += thirdKey;
	    err = gcry_cipher_setkey( context, keyCopy.data(), keyCopy.size() );
	} else {
	    err = gcry_cipher_setkey( context, key.data(), key.size() );
	}
	check_error( "gcry_cipher_setkey", err );
	err = gcry_cipher_setiv( context, iv.data(), iv.size() );
	check_error( "gcry_cipher_setiv", err );
    }

    Context *clone() const
    {
      return new gcryCipherContext( *this );
    }

    int blockSize() const
    {
	unsigned int blockSize;
	gcry_cipher_algo_info( m_cryptoAlgorithm, GCRYCTL_GET_BLKLEN, 0, (size_t*)&blockSize );
	return blockSize;
    }

    bool update(const QCA::SecureArray &in, QCA::SecureArray *out)
    {
        QCA::SecureArray result( in.size() );
	if (QCA::Encode == m_direction) {
	    err = gcry_cipher_encrypt( context, (unsigned char*)result.data(), result.size(), (unsigned char*)in.data(), in.size() );
	} else {
	    err = gcry_cipher_decrypt( context, (unsigned char*)result.data(), result.size(), (unsigned char*)in.data(), in.size() );
	}
	check_error( "update cipher encrypt/decrypt", err );
	result.resize( in.size() );
	*out = result;
	return true;
    }

    bool final(QCA::SecureArray *out)
    {
        QCA::SecureArray result;
	if (m_pad) {
	    result.resize( blockSize() );
	    if (QCA::Encode == m_direction) {
		err = gcry_cipher_encrypt( context, (unsigned char*)result.data(), result.size(), NULL, 0 );
	    } else {
		err = gcry_cipher_decrypt( context, (unsigned char*)result.data(), result.size(), NULL, 0 );
	    }
	    check_error( "final cipher encrypt/decrypt", err );
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
	    return QCA::KeyLength( 24, 24, 1);
	case GCRY_CIPHER_3DES:
	    // we do two and three key versions
	    return QCA::KeyLength( 16, 24, 8);
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


class pbkdf1Context : public QCA::KDFContext
{
public:
    pbkdf1Context(int algorithm, QCA::Provider *p, const QString &type) : QCA::KDFContext(p, type)
    {
	m_hashAlgorithm = algorithm;
	err =  gcry_md_open( &context, m_hashAlgorithm, 0 );
	if ( GPG_ERR_NO_ERROR != err ) {
	    std::cout << "Failure: " ;
	    std::cout << gcry_strsource(err) << "/";
	    std::cout << gcry_strerror(err) << std::endl;
	}
    }

    ~pbkdf1Context()
    {
	gcry_md_close( context );
    }

    Context *clone() const
    {
	return new pbkdf1Context( *this );
    }

    QCA::SymmetricKey makeKey(const QCA::SecureArray &secret, const QCA::InitializationVector &salt,
			      unsigned int keyLength, unsigned int iterationCount)
    {
	/* from RFC2898:
	   Steps:

	   1. If dkLen > 16 for MD2 and MD5, or dkLen > 20 for SHA-1, output
	   "derived key too long" and stop.
	*/
	if ( keyLength > gcry_md_get_algo_dlen(m_hashAlgorithm) ) {
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
	gcry_md_write( context, secret.data(), secret.size() );
	gcry_md_write( context, salt.data(), salt.size() );
	unsigned char *md;
	md = gcry_md_read( context, m_hashAlgorithm );
        QCA::SecureArray a( gcry_md_get_algo_dlen( m_hashAlgorithm ) );
	memcpy( a.data(), md, a.size() );

	// calculate T_2 up to T_c
	for ( unsigned int i = 2; i <= iterationCount; ++i ) {
	    gcry_md_reset( context );
	    gcry_md_write( context, a.data(), a.size() );
	    md = gcry_md_read( context, m_hashAlgorithm );
	    memcpy( a.data(), md, a.size() );
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
    int m_hashAlgorithm;
};


class pbkdf2Context : public QCA::KDFContext
{
public:
    pbkdf2Context(int algorithm, QCA::Provider *p, const QString &type) : QCA::KDFContext(p, type)
    {
	m_algorithm = algorithm;
    }

    Context *clone() const
    {
      return new pbkdf2Context( *this );
    }

    QCA::SymmetricKey makeKey(const QCA::SecureArray &secret, const QCA::InitializationVector &salt,
			 unsigned int keyLength, unsigned int iterationCount)
    {
	QCA::SymmetricKey result(keyLength);
	gcry_error_t retval = gcry_pbkdf2(m_algorithm, secret.data(), secret.size(),
					  salt.data(), salt.size(),
				     	  iterationCount, keyLength, result.data());
	if (retval == GPG_ERR_NO_ERROR) {
	    return result;
	} else {
	    // std::cout << "got: " << retval << std::endl;
	    return QCA::SymmetricKey();
	}
    }

protected:
    int m_algorithm;
};

}

extern "C"
{

static void * qca_func_malloc(size_t n)
{
    return qca_secure_alloc(n);
}

static void * qca_func_secure_malloc(size_t n)
{
    return qca_secure_alloc(n);
}

static void * qca_func_realloc(void *oldBlock, size_t newBlockSize)
{
    return qca_secure_realloc(oldBlock, newBlockSize);
}

static void qca_func_free(void *mem)
{
    qca_secure_free(mem);
}

int qca_func_secure_check (const void *)
{
    return (int)QCA::haveSecureMemory();
}
} // extern "C"

class gcryptProvider : public QCA::Provider
{
public:
    void init()
    {
	if (!gcry_control (GCRYCTL_ANY_INITIALIZATION_P))
	{ /* No other library has already initialized libgcrypt. */

	    if (!gcry_check_version (GCRYPT_VERSION) )
	    {
		std::cout << "libgcrypt is too old (need " << GCRYPT_VERSION;
		std::cout << ", have " << gcry_check_version(NULL) << ")" << std::endl;
	    }
	    gcry_set_allocation_handler (qca_func_malloc,
					 qca_func_secure_malloc,
					 qca_func_secure_check,
					 qca_func_realloc,
					 qca_func_free);
	    gcry_control (GCRYCTL_INITIALIZATION_FINISHED);
	}
    }

    int qcaVersion() const
    {
        return QCA_VERSION;
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
#ifdef GCRY_MD_SHA224
	list += "sha224";
#endif
	list += "sha256";
	list += "sha384";
	list += "sha512";
	list += "hmac(md5)";
	list += "hmac(sha1)";
#ifdef GCRY_MD_SHA224
	list += "hmac(sha224)";
#endif
	list += "hmac(sha256)";
	if ( ! ( NULL == gcry_check_version("1.3.0") ) ) {
	    // 1.2 and earlier have broken implementation
	    list += "hmac(sha384)";
	    list += "hmac(sha512)";
	}
	list += "hmac(ripemd160)";
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
	list += "blowfish-cbc";
	list += "blowfish-cfb";
	list += "tripledes-ecb";
	list += "des-ecb";
	list += "des-cbc";
	list += "des-cfb";
	if ( ! ( NULL == gcry_check_version("1.3.0") ) ) {
	    // 1.2 branch and earlier doesn't support OFB mode
	    list += "aes128-ofb";
	    list += "aes192-ofb";
	    list += "aes256-ofb";
	    list += "des-ofb";
	    list += "tripledes-ofb";
	    list += "blowfish-ofb";
	}
	list += "pbkdf1(sha1)";
	list += "pbkdf2(sha1)";
	return list;
    }

    Context *createContext(const QString &type)
    {
        // std::cout << "type: " << qPrintable(type) << std::endl;
	if ( type == "sha1" )
	    return new gcryptQCAPlugin::gcryHashContext( GCRY_MD_SHA1, this, type );
	else if ( type == "md4" )
	    return new gcryptQCAPlugin::gcryHashContext( GCRY_MD_MD4, this, type );
	else if ( type == "md5" )
	    return new gcryptQCAPlugin::gcryHashContext( GCRY_MD_MD5, this, type );
	else if ( type == "ripemd160" )
	    return new gcryptQCAPlugin::gcryHashContext( GCRY_MD_RMD160, this, type );
#ifdef GCRY_MD_SHA224
	else if ( type == "sha224" )
	    return new gcryptQCAPlugin::gcryHashContext( GCRY_MD_SHA224, this, type );
#endif
	else if ( type == "sha256" )
	    return new gcryptQCAPlugin::gcryHashContext( GCRY_MD_SHA256, this, type );
	else if ( type == "sha384" )
	    return new gcryptQCAPlugin::gcryHashContext( GCRY_MD_SHA384, this, type );
	else if ( type == "sha512" )
	    return new gcryptQCAPlugin::gcryHashContext( GCRY_MD_SHA512, this, type );
	else if ( type == "hmac(md5)" )
	    return new gcryptQCAPlugin::gcryHMACContext( GCRY_MD_MD5, this, type );
	else if ( type == "hmac(sha1)" )
	    return new gcryptQCAPlugin::gcryHMACContext( GCRY_MD_SHA1, this, type );
#ifdef GCRY_MD_SHA224
	else if ( type == "hmac(sha224)" )
	    return new gcryptQCAPlugin::gcryHMACContext( GCRY_MD_SHA224, this, type );
#endif
	else if ( type == "hmac(sha256)" )
	    return new gcryptQCAPlugin::gcryHMACContext( GCRY_MD_SHA256, this, type );
	else if ( type == "hmac(sha384)" )
	    return new gcryptQCAPlugin::gcryHMACContext( GCRY_MD_SHA384, this, type );
	else if ( type == "hmac(sha512)" )
	    return new gcryptQCAPlugin::gcryHMACContext( GCRY_MD_SHA512, this, type );
	else if ( type == "hmac(ripemd160)" )
	    return new gcryptQCAPlugin::gcryHMACContext( GCRY_MD_RMD160, this, type );
	else if ( type == "aes128-ecb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, false, this, type );
	else if ( type == "aes128-cfb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CFB, false, this, type );
	else if ( type == "aes128-ofb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_OFB, false, this, type );
	else if ( type == "aes128-cbc" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, false, this, type );
	else if ( type == "aes192-ecb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB, false, this, type );
	else if ( type == "aes192-cfb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CFB, false, this, type );
	else if ( type == "aes192-ofb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OFB, false, this, type );
	else if ( type == "aes192-cbc" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC, false, this, type );
	else if ( type == "aes256-ecb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, false, this, type );
	else if ( type == "aes256-cfb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, false, this, type );
	else if ( type == "aes256-ofb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB, false, this, type );
	else if ( type == "aes256-cbc" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, false, this, type );
	else if ( type == "blowfish-ecb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB, false, this, type );
	else if ( type == "blowfish-cbc" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CBC, false, this, type );
	else if ( type == "blowfish-cfb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CFB, false, this, type );
	else if ( type == "blowfish-ofb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_OFB, false, this, type );
	else if ( type == "tripledes-ecb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_ECB, false, this, type );
	else if ( type == "tripledes-ofb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_OFB, false, this, type );
	else if ( type == "des-ecb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, false, this, type );
	else if ( type == "des-cbc" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC, false, this, type );
	else if ( type == "des-cfb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CFB, false, this, type );
	else if ( type == "des-ofb" )
	    return new gcryptQCAPlugin::gcryCipherContext( GCRY_CIPHER_DES, GCRY_CIPHER_MODE_OFB, false, this, type );
	else if ( type == "pbkdf1(sha1)" )
	    return new gcryptQCAPlugin::pbkdf1Context( GCRY_MD_SHA1, this, type );
	else if ( type == "pbkdf2(sha1)" )
	    return new gcryptQCAPlugin::pbkdf2Context( GCRY_MD_SHA1, this, type );
	else
	    return 0;
    }
};

class gcryptPlugin : public QObject, public QCAPlugin
{
    Q_OBJECT
#if QT_VERSION >= 0x050000
	Q_PLUGIN_METADATA(IID "org.psi-im.qca-gcrypt")
#endif
    Q_INTERFACES(QCAPlugin)
	public:
    virtual QCA::Provider *createProvider() { return new gcryptProvider; }
};

#include "qca-gcrypt.moc"

#if QT_VERSION < 0x050000
Q_EXPORT_PLUGIN2(qca_gcrypt, gcryptPlugin)
#endif
