/*
 * Copyright (C) 2003-2005  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2004,2005  Brad Hards <bradh@frogmouth.net>
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

#include "qca_securelayer.h"

#include <QtCore>
#include "qcaprovider.h"

namespace QCA {

Provider::Context *getContext(const QString &type, const QString &provider);

//----------------------------------------------------------------------------
// SecureFilter
//----------------------------------------------------------------------------
SecureFilter::~SecureFilter()
{
}

bool SecureFilter::isClosable() const
{
	return false;
}

bool SecureFilter::haveClosed() const
{
	return false;
}

void SecureFilter::close()
{
}

QByteArray SecureFilter::readUnprocessed()
{
	return QByteArray();
}

//----------------------------------------------------------------------------
// SecureLayer
//----------------------------------------------------------------------------
SecureLayer::SecureLayer(QObject *parent)
:QObject(parent)
{
	_signals = true;
}

void SecureLayer::setStatefulOnly(bool b)
{
	_signals = !b;
}

void SecureLayer::layerUpdateBegin()
{
	_read = bytesAvailable();
	_readout = bytesOutgoingAvailable();
	_closed = haveClosed();
	_error = !ok();
}

void SecureLayer::layerUpdateEnd()
{
	if(_signals)
	{
		if(bytesAvailable() > _read)
			QTimer::singleShot(0, this, SIGNAL(readyRead()));
		if(bytesOutgoingAvailable() > _readout)
			QTimer::singleShot(0, this, SIGNAL(readyReadOutgoing()));
		if(!_closed && haveClosed())
			QTimer::singleShot(0, this, SIGNAL(closed()));
		if(!_error && !ok())
			QTimer::singleShot(0, this, SIGNAL(error()));
	}
}

//----------------------------------------------------------------------------
// TLS
//----------------------------------------------------------------------------
enum ResetMode
{
	ResetSession        = 0,
	ResetSessionAndData = 1,
	ResetAll            = 2
};

class TLS::Private
{
public:
	TLS *q;
	TLSContext *c;

	CertificateChain localCert;
	PrivateKey localKey;
	CertificateCollection trusted;
	bool con_ssfMode;
	int con_minSSF, con_maxSSF;
	QStringList con_cipherSuites;
	bool tryCompress;

	QString host;
	CertificateChain peerCert;
	Validity peerValidity;
	bool hostMismatch;
	TLSContext::SessionInfo sessionInfo;

	QSecureArray in, out;
	QByteArray to_net, from_net;

	bool handshaken, closing, closed, error;
	bool tryMore;
	int bytesEncoded;
	Error errorCode;

	Private(TLS *_q)
	{
		q = _q;
		c = 0;

		reset(ResetAll);
	}

	void reset(ResetMode mode = ResetSession)
	{
		if(c)
			c->reset();

		host = QString();
		out.clear();
		handshaken = false;
		closing = false;
		closed = false;
		error = false;
		tryMore = false;
		bytesEncoded = 0;

		if(mode >= ResetSessionAndData)
		{
			peerCert = CertificateChain();
			peerValidity = ErrorValidityUnknown;
			hostMismatch = false;
			in.clear();
			to_net.clear();
			from_net.clear();
		}

		if(mode >= ResetAll)
		{
			localCert = CertificateChain();
			localKey = PrivateKey();
			trusted = CertificateCollection();
			con_ssfMode = true;
			con_minSSF = 128;
			con_maxSSF = -1;
			con_cipherSuites = QStringList();
			tryCompress = false;
		}
	}

	bool start(bool serverMode)
	{
		if(con_ssfMode)
			c->setConstraints(con_minSSF, con_maxSSF);
		else
			c->setConstraints(con_cipherSuites);

		c->setup(trusted, localCert, localKey, tryCompress);

		bool ok;
		if(serverMode)
			ok = c->startServer();
		else
			ok = c->startClient();
		if(!ok)
			return false;

		update();
		return true;
	}

	void close()
	{
		if(!handshaken || closing)
			return;

		closing = true;
	}

	void update()
	{
		bool wasHandshaken = handshaken;
		q->layerUpdateBegin();

		if(closing)
			updateClosing();
		else
			updateMain();

		if(!wasHandshaken && handshaken)
			QTimer::singleShot(0, q, SIGNAL(handshaken()));
		q->layerUpdateEnd();
	}

	void updateClosing()
	{
		QByteArray a;
		TLSContext::Result r = c->shutdown(from_net, &a);
		from_net.clear();

		if(r == TLSContext::Error)
		{
			reset();
			error = true;
			errorCode = ErrorHandshake;
			return;
		}

		to_net.append(a);

		if(r == TLSContext::Success)
		{
			from_net = c->unprocessed();
			reset();
			closed = true;
			return;
		}
	}

	void updateMain()
	{
		bool force_read = false;

		if(!handshaken)
		{
			QByteArray a;
			TLSContext::Result r = c->handshake(from_net, &a);
			from_net.clear();

			if(r == TLSContext::Error)
			{
				reset();
				error = true;
				errorCode = ErrorHandshake;
				return;
			}

			to_net.append(a);

			if(r == TLSContext::Success)
			{
				peerCert = c->peerCertificateChain();
				if(!peerCert.isEmpty())
				{
					peerValidity = c->peerCertificateValidity();
					if(peerValidity == ValidityGood && !host.isEmpty() && !peerCert.primary().matchesHostname(host))
						hostMismatch = true;
				}
				sessionInfo = c->sessionInfo();
				handshaken = true;
				force_read = true;
			}
		}

		if(handshaken)
		{
			bool eof = false;

			if(!out.isEmpty() || tryMore)
			{
				tryMore = false;
				QByteArray a;
				int enc;
				bool more = false;
				bool ok = c->encode(out, &a, &enc);
				eof = c->eof();
				if(ok && enc < out.size())
					more = true;
				out.clear();
				if(!eof)
				{
					if(!ok)
					{
						reset();
						error = true;
						errorCode = ErrorCrypt;
						return;
					}
					bytesEncoded += enc;
					if(more)
						tryMore = true;
					to_net.append(a);
				}
			}

			if(!from_net.isEmpty() || force_read)
			{
				QSecureArray a;
				QByteArray b;
				bool ok = c->decode(from_net, &a, &b);
				eof = c->eof();
				from_net.clear();
				if(!ok)
				{
					reset();
					error = true;
					errorCode = ErrorCrypt;
					return;
				}
				in.append(a);
				to_net.append(b);
			}

			if(eof)
			{
				close();
				updateClosing();
				return;
			}
		}
	}
};

TLS::TLS(QObject *parent, const QString &provider)
:SecureLayer(parent), Algorithm("tls", provider)
{
	d = new Private(this);
	d->c = static_cast<TLSContext *>(context());
}

TLS::~TLS()
{
	delete d;
}

void TLS::reset()
{
	d->reset(ResetAll);
}

QStringList TLS::supportedCipherSuites(const QString &provider)
{
	QStringList list;
	const TLSContext *c = static_cast<const TLSContext *>(getContext("tls", provider));
	if(!c)
		return list;
	list = c->supportedCipherSuites();
	delete c;
	return list;
}

void TLS::setCertificate(const CertificateChain &cert, const PrivateKey &key)
{
	d->localCert = cert;
	d->localKey = key;
}

void TLS::setTrustedCertificates(const CertificateCollection &trusted)
{
	d->trusted = trusted;
}

void TLS::setConstraints(SecurityLevel s)
{
	int min;
	switch(s)
	{
		case SL_None:
			min = 0;
			break;
		case SL_Integrity:
			min = 1;
			break;
		case SL_Export:
			min = 40;
			break;
		case SL_Baseline:
			min = 128;
			break;
		case SL_High:
			min = 129;
			break;
		case SL_Highest:
			qMax(129, d->c->maxSSF());
			break;
	}
	d->con_ssfMode = true;
	d->con_minSSF = min;
	d->con_maxSSF = -1;
}

void TLS::setConstraints(int minSSF, int maxSSF)
{
	d->con_ssfMode = true;
	d->con_minSSF = minSSF;
	d->con_maxSSF = maxSSF;
}

void TLS::setConstraints(const QStringList &cipherSuiteList)
{
	d->con_ssfMode = false;
	d->con_cipherSuites = cipherSuiteList;
}

bool TLS::canCompress(const QString &provider)
{
	bool ok = false;
	const TLSContext *c = static_cast<const TLSContext *>(getContext("tls", provider));
	if(!c)
		return ok;
	ok = c->canCompress();
	delete c;
	return ok;
}

void TLS::setCompressionEnabled(bool b)
{
	d->tryCompress = b;
}

bool TLS::startClient(const QString &host)
{
	d->reset(ResetSessionAndData);
	d->host = host;
	return d->start(false);
}

bool TLS::startServer()
{
	d->reset(ResetSessionAndData);
	return d->start(true);
}

bool TLS::isHandshaken() const
{
	return d->handshaken;
}

bool TLS::isCompressed() const
{
	return d->sessionInfo.isCompressed;
}

TLS::Version TLS::version() const
{
	return d->sessionInfo.version;
}

QString TLS::cipherSuite() const
{
	return d->sessionInfo.cipherSuite;
}

int TLS::cipherBits() const
{
	return d->sessionInfo.cipherBits;
}

int TLS::cipherMaxBits() const
{
	return d->sessionInfo.cipherMaxBits;
}

TLS::Error TLS::errorCode() const
{
	return d->errorCode;
}

TLS::IdentityResult TLS::peerIdentityResult() const
{
	if(d->peerCert.isEmpty())
		return NoCertificate;

	if(d->peerValidity != ValidityGood)
		return InvalidCertificate;

	if(d->hostMismatch)
		return HostMismatch;

	return Valid;
}

Validity TLS::peerCertificateValidity() const
{
	return d->peerValidity;
}

CertificateChain TLS::localCertificateChain() const
{
	return d->localCert;
}

CertificateChain TLS::peerCertificateChain() const
{
	return d->peerCert;
}

bool TLS::isClosable() const
{
	return true;
}

bool TLS::haveClosed() const
{
	return d->closed;
}

bool TLS::ok() const
{
	return !d->error;
}

int TLS::bytesAvailable() const
{
	return d->in.size();
}

int TLS::bytesOutgoingAvailable() const
{
	return d->to_net.size();
}

void TLS::close()
{
	d->close();
	d->update();
}

void TLS::write(const QSecureArray &a)
{
	d->out.append(a);
	d->update();
}

QSecureArray TLS::read()
{
	QSecureArray a = d->in;
	d->in.clear();
	return a;
}

void TLS::writeIncoming(const QByteArray &a)
{
	d->from_net.append(a);
	d->update();
}

QByteArray TLS::readOutgoing(int *plainBytes)
{
	QByteArray a = d->to_net;
	d->to_net.clear();
	if(plainBytes)
		*plainBytes = d->bytesEncoded;
	d->bytesEncoded = 0;
	return a;
}

QByteArray TLS::readUnprocessed()
{
	QByteArray a = d->from_net;
	d->from_net.clear();
	return a;
}

//----------------------------------------------------------------------------
// SASL
//----------------------------------------------------------------------------
QString *saslappname = 0;
class SASL::Private
{
public:
	void setSecurityProps()
	{
		c->setSecurityProps(noPlain, noActive, noDict, noAnon, reqForward, reqCreds, reqMutual, ssfmin, ssfmax, ext_authid, ext_ssf);
	}

	// security opts
	bool noPlain, noActive, noDict, noAnon, reqForward, reqCreds, reqMutual;
	int ssfmin, ssfmax;
	QString ext_authid;
	int ext_ssf;

	bool tried;
	SASLContext *c;
	//QHostAddress localAddr, remoteAddr;
	int localPort, remotePort;
	QByteArray stepData;
	bool allowCSF;
	bool first, server;
	Error errorCode;

	QByteArray inbuf, outbuf;
};

SASL::SASL(QObject *parent, const QString &provider)
:SecureLayer(parent), Algorithm("sasl", provider)
{
	d = new Private;
	d->c = (SASLContext *)context();
	reset();
}

SASL::~SASL()
{
	delete d;
}

void SASL::reset()
{
	d->localPort = -1;
	d->remotePort = -1;

	d->noPlain = false;
	d->noActive = false;
	d->noDict = false;
	d->noAnon = false;
	d->reqForward = false;
	d->reqCreds = false;
	d->reqMutual = false;
	d->ssfmin = 0;
	d->ssfmax = 0;
	d->ext_authid = QString();
	d->ext_ssf = 0;

	d->inbuf.resize(0);
	d->outbuf.resize(0);

	d->c->reset();
}

SASL::Error SASL::errorCode() const
{
	return d->errorCode;
}

SASL::AuthCondition SASL::authCondition() const
{
	return (AuthCondition)d->c->authError();
}

void SASL::setConstraints(AuthFlags f, SecurityLevel s)
{
	Q_UNUSED(f);
	Q_UNUSED(s);

	/*d->noPlain    = (f & SAllowPlain) ? false: true;
	d->noAnon     = (f & SAllowAnonymous) ? false: true;
	//d->noActive   = (f & SAllowActiveVulnerable) ? false: true;
	//d->noDict     = (f & SAllowDictVulnerable) ? false: true;
	d->reqForward = (f & SRequireForwardSecrecy) ? true : false;
	d->reqCreds   = (f & SRequirePassCredentials) ? true : false;
	d->reqMutual  = (f & SRequireMutualAuth) ? true : false;*/

	//d->ssfmin = minSSF;
	//d->ssfmax = maxSSF;
}

void SASL::setConstraints(AuthFlags, int, int)
{
}

void SASL::setExternalAuthId(const QString &authid)
{
	d->ext_authid = authid;
}

void SASL::setExternalSSF(int x)
{
	d->ext_ssf = x;
}

void SASL::setLocalAddr(const QString &addr, quint16 port)
{
	Q_UNUSED(addr);
	//d->localAddr = addr;
	d->localPort = port;
}

void SASL::setRemoteAddr(const QString &addr, quint16 port)
{
	Q_UNUSED(addr);
	//d->remoteAddr = addr;
	d->remotePort = port;
}

bool SASL::startClient(const QString &service, const QString &host, const QStringList &mechlist, ClientSendMode)
{
	SASLContext::HostPort la, ra;
	/*if(d->localPort != -1) {
		la.addr = d->localAddr;
		la.port = d->localPort;
	}
	if(d->remotePort != -1) {
		ra.addr = d->remoteAddr;
		ra.port = d->remotePort;
	}*/

	//d->allowCSF = allowClientSendFirst;
	d->c->setCoreProps(service, host, d->localPort != -1 ? &la : 0, d->remotePort != -1 ? &ra : 0);
	d->setSecurityProps();

	if(!d->c->clientStart(mechlist))
		return false;
	d->first = true;
	d->server = false;
	d->tried = false;
	QTimer::singleShot(0, this, SLOT(tryAgain()));
	return true;
}

bool SASL::startServer(const QString &service, const QString &host, const QString &realm, QStringList *mechlist, ServerSendMode)
{
	//Q_UNUSED(allowServerSendLast);

	SASLContext::HostPort la, ra;
	/*if(d->localPort != -1) {
		la.addr = d->localAddr;
		la.port = d->localPort;
	}
	if(d->remotePort != -1) {
		ra.addr = d->remoteAddr;
		ra.port = d->remotePort;
	}*/

	d->c->setCoreProps(service, host, d->localPort != -1 ? &la : 0, d->remotePort != -1 ? &ra : 0);
	d->setSecurityProps();

	QString appname;
	if(saslappname)
		appname = *saslappname;
	else
		appname = "qca";

	if(!d->c->serverStart(realm, mechlist, appname))
		return false;
	d->first = true;
	d->server = true;
	d->tried = false;
	return true;
}

void SASL::putServerFirstStep(const QString &mech)
{
	/*int r =*/ d->c->serverFirstStep(mech, 0);
	//handleServerFirstStep(r);
}

void SASL::putServerFirstStep(const QString &mech, const QByteArray &clientInit)
{
	/*int r =*/ d->c->serverFirstStep(mech, &clientInit);
	//handleServerFirstStep(r);
}

void SASL::putStep(const QByteArray &stepData)
{
	d->stepData = stepData;
	//tryAgain();
}

void SASL::setUsername(const QString &user)
{
	d->c->setClientParams(&user, 0, 0, 0);
}

void SASL::setAuthzid(const QString &authzid)
{
	d->c->setClientParams(0, &authzid, 0, 0);
}

void SASL::setPassword(const QSecureArray &pass)
{
	d->c->setClientParams(0, 0, &pass, 0);
}

void SASL::setRealm(const QString &realm)
{
	d->c->setClientParams(0, 0, 0, &realm);
}

void SASL::continueAfterParams()
{
	//tryAgain();
}

void SASL::continueAfterAuthCheck()
{
	//tryAgain();
}

int SASL::ssf() const
{
	return d->c->security();
}

bool SASL::ok() const
{
	return false;
}

int SASL::bytesAvailable() const
{
	return 0;
}

int SASL::bytesOutgoingAvailable() const
{
	return 0;
}

void SASL::close()
{
}

void SASL::write(const QSecureArray &a)
{
	Q_UNUSED(a);
}

QSecureArray SASL::read()
{
	return QSecureArray();
}

void SASL::writeIncoming(const QByteArray &a)
{
	Q_UNUSED(a);
}

QByteArray SASL::readOutgoing(int *plainBytes)
{
	Q_UNUSED(plainBytes);
	return QByteArray();
}

}
