/*
 * Copyright (C) 2003,2004  Justin Karneges
 * Copyright (C) 2005  Brad Hards <bradh@frogmouth.net>
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

#include <QStringList>

namespace cyrusSASLQCAPlugin {
    class saslContext : public QCA::SASLContext
    {
    public:
	saslContext(QCA::Provider *p) : QCA::SASLContext(p)
	    {
	    }
	
	~saslContext()
	    {
	    }

	Context *clone() const
	    {
		return new saslContext(*this);
	    }
        
	void reset()
	    {
	    }

        void setCoreProps(const QString &service, const QString &host, HostPort *local, HostPort *remote)
	    {
		m_service = service;
		m_host = host;
	    }

	void setSecurityProps(bool noPlain, bool noActive, bool noDict, bool noAnon, bool reqForward, bool reqCreds, bool reqMutual, int ssfMin, int ssfMax, const QString &_ext_authid, int _ext_ssf)
	    {
	    }

	int security() const
	    {
		return m_security;
	    }

	AuthError authError() const
	    {
	    }

	bool clientStart(const QStringList &mechlist)
	    {
	    }

	int clientFirstStep(bool allowClientSendFirst)
	    {
	    }

	bool serverStart(const QString &realm, QStringList *mechlist, const QString &name)
	    {
	    }

	int serverFirstStep(const QString &mech, const QByteArray *in)
	    {
	    }

	AuthParams clientParamsNeeded() const
	    {
	    }

	void setClientParams(const QString *user, const QString *authzid, const QSecureArray *pass, const QString *realm)
	    {
	    }

	QString username() const
	    {
		return m_userName;
	    }

	QString authzid() const
	    {
		return m_authzid;
	    }

        int nextStep(const QByteArray &in)
	    {
	    }

	int tryAgain()
	    {
	    }

        QString mech() const
	    {
		return m_mechanism;
	    }

	const QByteArray *clientInit() const
	    {
	    }

        QByteArray result() const
	    {
	    }

        bool encode(const QSecureArray &in, QByteArray *out)
	    {
	    }

	bool decode(const QByteArray &in, QSecureArray *out)
	    {
	    }

    private:
	QString m_service;
	QString m_host;
	QString m_userName;
	QString m_authzid;

	QString m_mechanism;
	int m_security;
    };
}

class cyrusSASLProvider : public QCA::Provider
{
public:
    void init()
    { 
	// TODO
    }

    QString name() const
    {
	return "qca-cyrus-sasl";
    }
    
    QStringList features() const
    {
	QStringList list;
	list += "sasl";
	return list;
    }
    
    Context *createContext(const QString &type)
    {
	if ( type == "sasl" )
	    return new cyrusSASLQCAPlugin::saslContext( this );
	else
	    return 0;
    }
};

class cyrusSASLPlugin : public QCAPlugin
{
	Q_OBJECT
public:
	virtual int version() const { return QCA_PLUGIN_VERSION; }
	virtual QCA::Provider *createProvider() { return new cyrusSASLProvider; }
};

#include "qca-cyrus-sasl.moc"

Q_EXPORT_PLUGIN(cyrusSASLPlugin);


