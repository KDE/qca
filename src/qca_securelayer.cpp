/*
 * qca_securelayer.cpp - Qt Cryptographic Architecture
 * Copyright (C) 2004  Justin Karneges
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

#include "qca.h"

#include <qtimer.h>
#include <qhostaddress.h>
#include <qguardedptr.h>
#include "qcaprovider.h"

namespace QCA {

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

QSecureArray SecureFilter::readUnprocessed()
{
	return QSecureArray();
}

//----------------------------------------------------------------------------
// SecureLayer
//----------------------------------------------------------------------------
SecureLayer::SecureLayer(QObject *parent, const char *name)
:QObject(parent, name)
{
}

void SecureLayer::layerUpdateBegin()
{
	_read = bytesAvailable();
	_readout = bytesOutgoingAvailable();
	_closed = haveClosed();
	_error = haveError();
}

void SecureLayer::layerUpdateEnd()
{
	if(_read > bytesAvailable())
		QTimer::singleShot(0, this, SIGNAL(readyRead()));
	if(_readout > bytesOutgoingAvailable())
		QTimer::singleShot(0, this, SIGNAL(readyReadOutgoing()));
	if(!_closed && haveClosed())
		QTimer::singleShot(0, this, SIGNAL(closed()));
	if(!_error && haveError())
		QTimer::singleShot(0, this, SIGNAL(error()));
}

//----------------------------------------------------------------------------
// TLS
//----------------------------------------------------------------------------
class TLS::Private
{
public:
	Private()
	{
		store = 0;
	}

	void reset()
	{
		handshaken = false;
		closing = false;
		in.resize(0);
		out.resize(0);
		from_net.resize(0);
		to_net.resize(0);
		host = "";
		hostMismatch = false;
		cert = Certificate();
		bytesEncoded = 0;
		tryMore = false;
	}

	void appendArray(QByteArray *a, const QByteArray &b)
	{
		int oldsize = a->size();
		a->resize(oldsize + b.size());
		memcpy(a->data() + oldsize, b.data(), b.size());
	}

	Certificate cert;
	CertValidity certValidity;
	TLSContext *c;
	QByteArray in, out, to_net, from_net;
	int bytesEncoded;
	bool tryMore;
	bool handshaken;
	QString host;
	bool hostMismatch;
	bool closing;
	Error errorCode;

	Certificate ourCert;
	PrivateKey ourKey;
	Store *store;
};

TLS::TLS(QObject *parent, const char *name, const QString &provider)
:SecureLayer(parent, name), Algorithm("tls", provider)
{
	d = new Private;
	d->c = (TLSContext *)context();
}

TLS::~TLS()
{
	delete d;
}

void TLS::setCertificate(const Certificate &cert, const PrivateKey &key)
{
	d->ourCert = cert;
	d->ourKey = key;
}

void TLS::setStore(const Store &store)
{
	d->store = new Store(store);
}

void TLS::reset()
{
	d->reset();
	// TODO: d->c->reset ??
}

bool TLS::startClient(const QString &host)
{
	d->reset();
	d->host = host;

	if(!d->c->startClient(*((StoreContext *)d->store->context()), *((CertContext *)d->ourCert.context()), *((PKeyContext *)d->ourKey.context())))
		return false;
	QTimer::singleShot(0, this, SLOT(update()));
	return true;
}

bool TLS::startServer()
{
	d->reset();

	if(!d->c->startServer(*((StoreContext *)d->store->context()), *((CertContext *)d->ourCert.context()), *((PKeyContext *)d->ourKey.context())))
		return false;
	QTimer::singleShot(0, this, SLOT(update()));
	return true;
}

void TLS::close()
{
	if(!d->handshaken || d->closing)
		return;

	d->closing = true;
	QTimer::singleShot(0, this, SLOT(update()));
}

bool TLS::isHandshaken() const
{
	return d->handshaken;
}

TLS::Error TLS::errorCode() const
{
	return d->errorCode;
}

bool TLS::isClosable() const
{
	return true;
}

bool TLS::haveClosed() const
{
	return false;
}

bool TLS::haveError() const
{
	return false;
}

int TLS::bytesAvailable() const
{
	return 0;
}

int TLS::bytesOutgoingAvailable() const
{
	return 0;
}

void TLS::write(const QSecureArray &a)
{
	d->appendArray(&d->out, a.toByteArray());
	update();
}

QSecureArray TLS::read()
{
	QByteArray a = d->in.copy();
	d->in.resize(0);
	return a;
}

void TLS::writeIncoming(const QByteArray &a)
{
	d->appendArray(&d->from_net, a);
	update();
}

QByteArray TLS::readOutgoing()
{
	QByteArray a = d->to_net.copy();
	d->to_net.resize(0);
	return a;
}

QSecureArray TLS::readUnprocessed()
{
	QByteArray a = d->from_net.copy();
	d->from_net.resize(0);
	return a;
}

TLS::IdentityResult TLS::peerIdentityResult() const
{
	if(d->cert.isNull())
		return NoCert;

	if(d->certValidity != QCA::Valid)
		return BadCert;

	if(d->hostMismatch)
		return HostMismatch;

	return Valid;
}

CertValidity TLS::peerCertificateValidity() const
{
	return d->certValidity;
}

Certificate TLS::localCertificate() const
{
	return d->ourCert;
}

Certificate TLS::peerCertificate() const
{
	return d->cert;
}

void TLS::update()
{
	bool force_read = false;
	bool eof = false;
	bool done = false;
	QGuardedPtr<TLS> self = this;

	if(d->closing) {
		QByteArray a;
		int r = d->c->shutdown(d->from_net, &a);
		d->from_net.resize(0);
		if(r == TLSContext::Error) {
			reset();
			d->errorCode = ErrHandshake;
			error();
			return;
		}
		if(r == TLSContext::Success) {
			d->from_net = d->c->unprocessed().toByteArray().copy();
			done = true;
		}
		d->appendArray(&d->to_net, a);
	}
	else {
		if(!d->handshaken) {
			QByteArray a;
			int r = d->c->handshake(d->from_net, &a);
			d->from_net.resize(0);
			if(r == TLSContext::Error) {
				reset();
				d->errorCode = ErrHandshake;
				error();
				return;
			}
			d->appendArray(&d->to_net, a);
			if(r == TLSContext::Success) {
				/*Certificate cert = d->c->peerCertificate();
				d->certValidity = d->c->peerCertificateValidity();
				if(!cert.isNull() && !d->host.isEmpty() && d->certValidity == QCA::Valid) {
					if(!cert.matchesAddress(d->host))
						d->hostMismatch = true;
				}
				d->cert = cert;*/
				d->handshaken = true;
				handshaken();
				if(!self)
					return;

				// there is a teeny tiny possibility that incoming data awaits.  let us get it.
				force_read = true;
			}
		}

		if(d->handshaken) {
			if(!d->out.isEmpty() || d->tryMore) {
				d->tryMore = false;
				QByteArray a;
				int enc;
				bool more = false;
				bool ok = d->c->encode(d->out, &a, &enc);
				eof = d->c->eof();
				if(ok && enc < (int)d->out.size())
					more = true;
				d->out.resize(0);
				if(!eof) {
					if(!ok) {
						reset();
						d->errorCode = ErrCrypt;
						error();
						return;
					}
					d->bytesEncoded += enc;
					if(more)
						d->tryMore = true;
					d->appendArray(&d->to_net, a);
				}
			}
			if(!d->from_net.isEmpty() || force_read) {
				QSecureArray a;
				QByteArray b;
				bool ok = d->c->decode(d->from_net, &a, &b);
				eof = d->c->eof();
				d->from_net.resize(0);
				if(!ok) {
					reset();
					d->errorCode = ErrCrypt;
					error();
					return;
				}
				d->appendArray(&d->in, a.toByteArray());
				d->appendArray(&d->to_net, b);
			}

			if(!d->in.isEmpty()) {
				readyRead();
				if(!self)
					return;
			}
		}
	}

	if(!d->to_net.isEmpty()) {
		//int bytes = d->bytesEncoded;
		d->bytesEncoded = 0;
		readyReadOutgoing();
		if(!self)
			return;
	}

	if(eof) {
		close();
		if(!self)
			return;
		return;
	}

	if(d->closing && done) {
		reset();
		closed();
	}
}

//----------------------------------------------------------------------------
// SASL
//----------------------------------------------------------------------------
/*QString *saslappname = 0;
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
	QHostAddress localAddr, remoteAddr;
	int localPort, remotePort;
	QByteArray stepData;
	bool allowCSF;
	bool first, server;
	Error errorCode;

	QByteArray inbuf, outbuf;
};

SASL::SASL(QObject *parent, const char *name, const QString &provider)
:SecureLayer(parent, name), Algorithm(F_SASL, provider)
{
	d = new Private;
	d->c = (SASLContext *)context();
	reset();
}

SASL::~SASL()
{
	delete d;
}

void SASL::setAppName(const QString &name)
{
	if(!saslappname)
		saslappname = new QString;
	*saslappname = name;
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
	d->ext_authid = "";
	d->ext_ssf = 0;

	d->inbuf.resize(0);
	d->outbuf.resize(0);

	d->c->reset();
}

SASL::Error SASL::errorCode() const
{
	return d->errorCode;
}

SASL::AuthCond SASL::authCondition() const
{
	return d->c->authCond();
}

void SASL::setConstraints(SecurityFlags f, int minSSF, int maxSSF)
{
	d->noPlain    = (f & SAllowPlain) ? false: true;
	d->noAnon     = (f & SAllowAnonymous) ? false: true;
	d->noActive   = (f & SAllowActiveVulnerable) ? false: true;
	d->noDict     = (f & SAllowDictVulnerable) ? false: true;
	d->reqForward = (f & SRequireForwardSecrecy) ? true : false;
	d->reqCreds   = (f & SRequirePassCredentials) ? true : false;
	d->reqMutual  = (f & SRequireMutualAuth) ? true : false;

	d->ssfmin = minSSF;
	d->ssfmax = maxSSF;
}

void SASL::setExternalAuthID(const QString &authid)
{
	d->ext_authid = authid;
}

void SASL::setExternalSSF(int x)
{
	d->ext_ssf = x;
}

void SASL::setLocalAddr(const QHostAddress &addr, Q_UINT16 port)
{
	d->localAddr = addr;
	d->localPort = port;
}

void SASL::setRemoteAddr(const QHostAddress &addr, Q_UINT16 port)
{
	d->remoteAddr = addr;
	d->remotePort = port;
}

bool SASL::startClient(const QString &service, const QString &host, const QStringList &mechlist, bool allowClientSendFirst)
{
	QCA_SASLHostPort la, ra;
	if(d->localPort != -1) {
		la.addr = d->localAddr;
		la.port = d->localPort;
	}
	if(d->remotePort != -1) {
		ra.addr = d->remoteAddr;
		ra.port = d->remotePort;
	}

	d->allowCSF = allowClientSendFirst;
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

bool SASL::startServer(const QString &service, const QString &host, const QString &realm, QStringList *mechlist)
{
	QCA_SASLHostPort la, ra;
	if(d->localPort != -1) {
		la.addr = d->localAddr;
		la.port = d->localPort;
	}
	if(d->remotePort != -1) {
		ra.addr = d->remoteAddr;
		ra.port = d->remotePort;
	}

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
	int r = d->c->serverFirstStep(mech, 0);
	handleServerFirstStep(r);
}

void SASL::putServerFirstStep(const QString &mech, const QByteArray &clientInit)
{
	int r = d->c->serverFirstStep(mech, &clientInit);
	handleServerFirstStep(r);
}

void SASL::handleServerFirstStep(int r)
{
	if(r == SASLContext::Success)
		authenticated();
	else if(r == SASLContext::Continue)
		nextStep(d->c->result());
	else if(r == SASLContext::AuthCheck)
		tryAgain();
	else {
		d->errorCode = ErrAuth;
		error();
	}
}

void SASL::putStep(const QByteArray &stepData)
{
	d->stepData = stepData.copy();
	tryAgain();
}

void SASL::setUsername(const QString &user)
{
	d->c->setClientParams(&user, 0, 0, 0);
}

void SASL::setAuthzid(const QString &authzid)
{
	d->c->setClientParams(0, &authzid, 0, 0);
}

void SASL::setPassword(const QString &pass)
{
	d->c->setClientParams(0, 0, &pass, 0);
}

void SASL::setRealm(const QString &realm)
{
	d->c->setClientParams(0, 0, 0, &realm);
}

void SASL::continueAfterParams()
{
	tryAgain();
}

void SASL::continueAfterAuthCheck()
{
	tryAgain();
}

void SASL::tryAgain()
{
	int r;

	if(d->server) {
		if(!d->tried) {
			r = d->c->nextStep(d->stepData);
			d->tried = true;
		}
		else {
			r = d->c->tryAgain();
		}

		if(r == SASLContext::Error) {
			d->errorCode = ErrAuth;
			error();
			return;
		}
		else if(r == SASLContext::Continue) {
			d->tried = false;
			nextStep(d->c->result());
			return;
		}
		else if(r == SASLContext::AuthCheck) {
			authCheck(d->c->username(), d->c->authzid());
			return;
		}
	}
	else {
		if(d->first) {
			if(!d->tried) {
				r = d->c->clientFirstStep(d->allowCSF);
				d->tried = true;
			}
			else
				r = d->c->tryAgain();

			if(r == SASLContext::Error) {
				d->errorCode = ErrAuth;
				error();
				return;
			}
			else if(r == SASLContext::NeedParams) {
				//d->tried = false;
				QCA_SASLNeedParams np = d->c->clientParamsNeeded();
				needParams(np.user, np.authzid, np.pass, np.realm);
				return;
			}

			QString mech = d->c->mech();
			const QByteArray *clientInit = d->c->clientInit();

			d->first = false;
			d->tried = false;
			clientFirstStep(mech, clientInit);
		}
		else {
			if(!d->tried) {
				r = d->c->nextStep(d->stepData);
				d->tried = true;
			}
			else
				r = d->c->tryAgain();

			if(r == SASLContext::Error) {
				d->errorCode = ErrAuth;
				error();
				return;
			}
			else if(r == SASLContext::NeedParams) {
				//d->tried = false;
				QCA_SASLNeedParams np = d->c->clientParamsNeeded();
				needParams(np.user, np.authzid, np.pass, np.realm);
				return;
			}
			d->tried = false;
			//else if(r == QCA_SASLContext::Continue) {
				nextStep(d->c->result());
			//	return;
			//}
		}
	}

	if(r == SASLContext::Success)
		authenticated();
	else if(r == SASLContext::Error) {
		d->errorCode = ErrAuth;
		error();
	}
}

int SASL::ssf() const
{
	return d->c->security();
}

void SASL::write(const QByteArray &a)
{
	QByteArray b;
	if(!d->c->encode(a, &b)) {
		d->errorCode = ErrCrypt;
		error();
		return;
	}
	int oldsize = d->outbuf.size();
	d->outbuf.resize(oldsize + b.size());
	memcpy(d->outbuf.data() + oldsize, b.data(), b.size());
	readyReadOutgoing(a.size());
}

QByteArray SASL::read()
{
	QByteArray a = d->inbuf.copy();
	d->inbuf.resize(0);
	return a;
}

void SASL::writeIncoming(const QByteArray &a)
{
	QByteArray b;
	if(!d->c->decode(a, &b)) {
		d->errorCode = ErrCrypt;
		error();
		return;
	}
	int oldsize = d->inbuf.size();
	d->inbuf.resize(oldsize + b.size());
	memcpy(d->inbuf.data() + oldsize, b.data(), b.size());
	readyRead();
}

QByteArray SASL::readOutgoing()
{
	QByteArray a = d->outbuf.copy();
	d->outbuf.resize(0);
	return a;
}
*/
}
