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
#include "pk11func.h"
#include "nss.h"
#include "hasht.h"

#include <QtCrypto>

#include <QDebug>
#include <QtPlugin>
#include <QStringList>


//-----------------------------------------------------------
class nssHashContext : public QCA::HashContext
{
public:
    nssHashContext( QCA::Provider *p, const QString &type) : QCA::HashContext(p, type)
    {
	SECStatus s;

	NSS_NoDB_Init(".");

	m_status = 0;

	/* Get a slot to use for the crypto operations */
	m_slot = PK11_GetInternalKeySlot();
	if (!m_slot)
	{
	    qDebug() << "GetInternalKeySlot failed";
	    m_status = 1;
	    return;
	}

	if ( QString("md2") == type ) {
	    m_hashAlgo = SEC_OID_MD2;
	}
	else if ( QString("md5") == type ) {
	    m_hashAlgo = SEC_OID_MD5;
	}
	else if ( QString("sha1") == type ) {
	    m_hashAlgo = SEC_OID_SHA1;
	}
	else if ( QString("sha256") == type ) {
	    m_hashAlgo = SEC_OID_SHA256;
	}
	else if ( QString("sha384") == type ) {
	    m_hashAlgo = SEC_OID_SHA384;
	}
	else if ( QString("sha512") == type ) {
	    m_hashAlgo = SEC_OID_SHA512;
	} else {
	    qDebug() << "Unknown provider type: " << type;
	    return; /* this will probably cause a segfault... */
	}

	m_context = PK11_CreateDigestContext(m_hashAlgo);
	if (! m_context) {
	    qDebug() << "CreateDigestContext failed";
	    return;
	}

	s = PK11_DigestBegin(m_context);
	if (s != SECSuccess) {
	    qDebug() << "DigestBegin failed";
	    return;
	}
    }

    ~nssHashContext()
    {
	PK11_DestroyContext(m_context, PR_TRUE);
	if (m_slot)
	    PK11_FreeSlot(m_slot);
    }

    Context *clone() const
    {
	return new nssHashContext(*this);
    }

    void clear()
    {
	SECStatus s;

	PK11_DestroyContext(m_context, PR_TRUE);

	m_context = PK11_CreateDigestContext(m_hashAlgo);
	if (! m_context) {
	    qDebug() << "CreateDigestContext failed";
	    return;
	}

	s = PK11_DigestBegin(m_context);
	if (s != SECSuccess) {
	    qDebug() << "DigestBegin failed";
	    return;
	}
    }

    void update(const QCA::MemoryRegion &a)
    {
	PK11_DigestOp(m_context, (const unsigned char*)a.data(), a.size());
    }

    QCA::MemoryRegion final()
    {
	unsigned int len = 0;
	QCA::SecureArray a( 64 );
	PK11_DigestFinal(m_context, (unsigned char*)a.data(), &len, a.size());
	a.resize(len);
	return a;
    }

private:
    PK11SlotInfo *m_slot;
    int m_status;
    PK11Context *m_context;
    SECOidTag m_hashAlgo;
};


//-----------------------------------------------------------
class nssHmacContext : public QCA::MACContext
{
public:
    nssHmacContext( QCA::Provider *p, const QString &type) : QCA::MACContext(p, type)
    {
	NSS_NoDB_Init(".");

	m_status = 0;

	/* Get a slot to use for the crypto operations */
	m_slot = PK11_GetInternalKeySlot();
	if (!m_slot)
	{
	    qDebug() << "GetInternalKeySlot failed";
	    m_status = 1;
	    return;
	}

	if ( QString("hmac(md5)") == type ) {
	    m_macAlgo = CKM_MD5_HMAC;
	}
	else if ( QString("hmac(sha1)") == type ) {
	    m_macAlgo = CKM_SHA_1_HMAC;
	}
	else if ( QString("hmac(sha256)") == type ) {
	    m_macAlgo = CKM_SHA256_HMAC;
	}
	else if ( QString("hmac(sha384)") == type ) {
	    m_macAlgo = CKM_SHA384_HMAC;
	}
	else if ( QString("hmac(sha512)") == type ) {
	    m_macAlgo = CKM_SHA512_HMAC;
	}
	else if ( QString("hmac(ripemd160)") == type ) {
	    m_macAlgo = CKM_RIPEMD160_HMAC;
	}
	else {
	    qDebug() << "Unknown provider type: " << type;
	    return; /* this will probably cause a segfault... */
	}
    }

    ~nssHmacContext()
    {
	PK11_DestroyContext(m_context, PR_TRUE);
	if (m_slot)
	    PK11_FreeSlot(m_slot);
    }

    Context *clone() const
    {
	return new nssHmacContext(*this);
    }

    void clear()
    {
	PK11_DestroyContext(m_context, PR_TRUE);

	SECItem noParams;
	noParams.data = 0;
	noParams.len = 0;

	m_context = PK11_CreateContextBySymKey(m_macAlgo, CKA_SIGN, m_nssKey, &noParams);
	if (! m_context) {
	    qDebug() << "CreateContextBySymKey failed";
	    return;
	}

	SECStatus s = PK11_DigestBegin(m_context);
	if (s != SECSuccess) {
	    qDebug() << "DigestBegin failed";
	    return;
	}
    }

    QCA::KeyLength keyLength() const
    {
        return anyKeyLength();
    }

    void setup(const QCA::SymmetricKey &key)
    {
        /* turn the raw key into a SECItem */
        SECItem keyItem;
	keyItem.data = (unsigned char*) key.data();
	keyItem.len = key.size();

	m_nssKey = PK11_ImportSymKey(m_slot, m_macAlgo, PK11_OriginUnwrap, CKA_SIGN, &keyItem, NULL);

	SECItem noParams;
	noParams.data = 0;
	noParams.len = 0;

	m_context = PK11_CreateContextBySymKey(m_macAlgo, CKA_SIGN, m_nssKey, &noParams);
	if (! m_context) {
	    qDebug() << "CreateContextBySymKey failed";
	    return;
	}

	SECStatus s = PK11_DigestBegin(m_context);
	if (s != SECSuccess) {
	    qDebug() << "DigestBegin failed";
	    return;
	}
    }

    void update(const QCA::MemoryRegion &a)
    {
	PK11_DigestOp(m_context, (const unsigned char*)a.data(), a.size());
    }

    void final( QCA::MemoryRegion *out)
    {
	// NSS doesn't appear to be able to tell us how big the digest will
	// be for a given algorithm until after we finalise it, so we work
	// around the problem a bit.
	QCA::SecureArray sa( HASH_LENGTH_MAX, 0 ); // assume the biggest hash size we know
	unsigned int len = 0;
	PK11_DigestFinal(m_context, (unsigned char*)sa.data(), &len, sa.size());
	sa.resize(len); // and fix it up later
	*out = sa;
    }

private:
    PK11SlotInfo *m_slot;
    int m_status;
    PK11Context *m_context;
    CK_MECHANISM_TYPE m_macAlgo;
    PK11SymKey* m_nssKey;
};

//-----------------------------------------------------------
class nssCipherContext : public QCA::CipherContext
{
public:
    nssCipherContext( QCA::Provider *p, const QString &type) : QCA::CipherContext(p, type)
    {
	NSS_NoDB_Init(".");

	if ( QString("aes128-ecb") == type ) {
	    m_cipherMechanism = CKM_AES_ECB;
	}
	else if ( QString("aes128-cbc") == type ) {
	    m_cipherMechanism = CKM_AES_CBC;
	}
	else if ( QString("des-ecb") == type ) {
	    m_cipherMechanism = CKM_DES_ECB;
	}
	else if ( QString("des-cbc") == type ) {
	    m_cipherMechanism = CKM_DES_CBC;
	}
	else if ( QString("des-cbc-pkcs7") == type ) {
	    m_cipherMechanism = CKM_DES_CBC_PAD;
	}
	else if ( QString("tripledes-ecb") == type ) {
	    m_cipherMechanism = CKM_DES3_ECB;
	}
	else {
	    qDebug() << "Unknown provider type: " << type;
	    return; /* this will probably cause a segfault... */
	}
    }

    ~nssCipherContext()
	{
	}

    void setup( QCA::Direction dir,
		const QCA::SymmetricKey &key,
		const QCA::InitializationVector &iv )
    {
	/* Get a slot to use for the crypto operations */
	m_slot = PK11_GetBestSlot( m_cipherMechanism, NULL );
	if (!m_slot)
	{
	    qDebug() << "GetBestSlot failed";
	    return;
	}

	/* turn the raw key into a SECItem */
        SECItem keyItem;
	keyItem.data = (unsigned char*) key.data();
	keyItem.len = key.size();

	if (QCA::Encode == dir) {
	    m_nssKey = PK11_ImportSymKey(m_slot, m_cipherMechanism,
					 PK11_OriginUnwrap, CKA_ENCRYPT,
					 &keyItem, NULL);
	} else {
	    // decryption
	    m_nssKey = PK11_ImportSymKey(m_slot, m_cipherMechanism,
					 PK11_OriginUnwrap, CKA_DECRYPT,
					 &keyItem, NULL);
	}

	SECItem ivItem;
	ivItem.data = (unsigned char*) iv.data();
	ivItem.len = iv.size();

	m_params = PK11_ParamFromIV(m_cipherMechanism, &ivItem);

	if (QCA::Encode == dir) {
	    m_context = PK11_CreateContextBySymKey(m_cipherMechanism,
						   CKA_ENCRYPT, m_nssKey,
						   m_params);
	} else {
	    // decryption
	    m_context = PK11_CreateContextBySymKey(m_cipherMechanism,
						   CKA_DECRYPT, m_nssKey,
						   m_params);
	}

	if (! m_context) {
	    qDebug() << "CreateContextBySymKey failed";
	    return;
	}
    }

    QCA::Provider::Context *clone() const
	{
	    return new nssCipherContext(*this);
	}

    int blockSize() const
	{
	    return PK11_GetBlockSize( m_cipherMechanism, m_params);
	}

    bool update( const QCA::SecureArray &in, QCA::SecureArray *out )
	{
	    out->resize(in.size()+blockSize());
	    int resultLength;

	    PK11_CipherOp(m_context, (unsigned char*)out->data(),
			  &resultLength, out->size(),
			  (unsigned char*)in.data(), in.size());
	    out->resize(resultLength);

	    return true;
	}

    bool final( QCA::SecureArray *out )
	{
	    out->resize(blockSize());
	    unsigned int resultLength;

	    PK11_DigestFinal(m_context, (unsigned char*)out->data(),
			     &resultLength, out->size());
	    out->resize(resultLength);

	    return true;
	}

    QCA::KeyLength keyLength() const
	{
		return QCA::KeyLength(0, 0, 0);
	}

private:
    PK11SymKey* m_nssKey;
    CK_MECHANISM_TYPE m_cipherMechanism;
    PK11SlotInfo *m_slot;
    PK11Context *m_context;
    SECItem* m_params;
};


//==========================================================
class nssProvider : public QCA::Provider
{
public:
    void init()
    {
    }

    ~nssProvider()
    {
    }

    int qcaVersion() const
    {
	return QCA_VERSION;
    }

    QString name() const
    {
	return "qca-nss";
    }

    QStringList features() const
    {
	QStringList list;

	list += "md2";
	list += "md5";
	list += "sha1";
	list += "sha256";
	list += "sha384";
	list += "sha512";

	list += "hmac(md5)";
	list += "hmac(sha1)";
	list += "hmac(sha256)";
	list += "hmac(sha384)";
	list += "hmac(sha512)";
	// appears to not be implemented in NSS yet
	// list += "hmac(ripemd160)";

	list += "aes128-ecb";
	list += "aes128-cbc";
	list += "des-ecb";
	list += "des-cbc";
	list += "des-cbc-pkcs7";
	list += "tripledes-ecb";

	return list;
    }

    Context *createContext(const QString &type)
    {
	if ( type == "md2" )
	    return new nssHashContext( this, type );
	if ( type == "md5" )
	    return new nssHashContext( this, type );
	if ( type == "sha1" )
	    return new nssHashContext( this, type );
	if ( type == "sha256" )
	    return new nssHashContext( this, type );
	if ( type == "sha384" )
	    return new nssHashContext( this, type );
	if ( type == "sha512" )
	    return new nssHashContext( this, type );

	if ( type == "hmac(md5)" )
	    return new nssHmacContext( this, type );
	if ( type == "hmac(sha1)" )
	    return new nssHmacContext( this, type );
	if ( type == "hmac(sha256)" )
	    return new nssHmacContext( this, type );
	if ( type == "hmac(sha384)" )
	    return new nssHmacContext( this, type );
	if ( type == "hmac(sha512)" )
	    return new nssHmacContext( this, type );
	if ( type == "hmac(ripemd160)" )
	    return new nssHmacContext( this, type );

	if ( type == "aes128-ecb" )
	    return new nssCipherContext( this, type);
	if ( type == "aes128-cbc" )
	    return new nssCipherContext( this, type);
	if ( type == "des-ecb" )
	    return new nssCipherContext( this, type);
	if ( type == "des-cbc" )
	    return new nssCipherContext( this, type);
	if ( type == "des-cbc-pkcs7" )
	    return new nssCipherContext( this, type);
	if ( type == "tripledes-ecb" )
	    return new nssCipherContext( this, type);
	else
	    return 0;
    }
};

class nssPlugin : public QObject, public QCAPlugin
{
	Q_OBJECT
#if QT_VERSION >= 0x050000
	Q_PLUGIN_METADATA(IID "org.psi-im.qca-nss")
#endif
	Q_INTERFACES( QCAPlugin )
public:
	virtual QCA::Provider *createProvider() { return new nssProvider; }
};

#include "qca-nss.moc"

#if QT_VERSION < 0x050000
Q_EXPORT_PLUGIN2(qca_nss, nssPlugin)
#endif
