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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include "pk11func.h"
#include "nss.h"

#include <QtCrypto>
#include <QtCore>

#include <qstringlist.h>


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
    
    void update(const QSecureArray &a)
    {
	PK11_DigestOp(m_context, (const unsigned char*)a.data(), a.size());
    }
    
    QSecureArray final()
    {
	unsigned int len = 0;
	QSecureArray a( 64 );
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
	else
	    return 0;
    }
private:

};

class nssPlugin : public QCAPlugin
{
	Q_OBJECT
	Q_INTERFACES( QCAPlugin )
public:
	virtual QCA::Provider *createProvider() { return new nssProvider; }
};

#include "qca-nss.moc"

Q_EXPORT_PLUGIN2(qca-nss, nssPlugin);


