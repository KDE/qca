/*
 * qca_securelayer.h - Qt Cryptographic Architecture
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

#ifndef QCA_SECURELAYER_H
#define QCA_SECURELAYER_H

#include <qobject.h>
#include "qca_core.h"
#include "qca_publickey.h"
#include "qca_cert.h"

class QHostAddress;

namespace QCA
{
	/**
	 * Specify the lower-bound for acceptable TLS/SASL security layers
	 */
	enum SecurityLevel
	{
		SL_None,      ///< indicates that no security is ok
		SL_Integrity, ///< must at least get integrity protection
		SL_Export,    ///< must be export level bits or more
		SL_Baseline,  ///< must be 128 bit or more
		SL_High,      ///< must be more than 128 bit
		SL_Highest    ///< SL_High or max possible, whichever is greater
	};

	// securefilter basic rule: after calling a function that might
	//  affect something, call others to get the results.
	//
	// write: call readOutgoing
	// writeIncoming: call haveClosed/haveError, read, and readOutgoing
	// close: call haveClosed/haveError and readOutgoing
	// haveClosed: if Closed, call readUnprocessed
	class QCA_EXPORT SecureFilter
	{
	public:
		virtual ~SecureFilter();

		virtual bool isClosable() const;
		virtual bool haveClosed() const;
		virtual bool haveError() const = 0;
		virtual int bytesAvailable() const = 0;
		virtual int bytesOutgoingAvailable() const = 0;
		virtual void close();

		// plain (application side)
		virtual void write(const QSecureArray &a) = 0;
		virtual QSecureArray read() = 0;

		// encoded (network side)
		virtual void writeIncoming(const QByteArray &a) = 0;
		virtual QByteArray readOutgoing(int *plainBytes = 0) = 0;
		virtual QSecureArray readUnprocessed();
	};

	// securelayer - "nicer" interface, using signals.  subclass
	//  should call layerUpdateBegin/End before and after write,
	//  writeIncoming, or close.
	class QCA_EXPORT SecureLayer : public QObject, public SecureFilter
	{
		Q_OBJECT
	public:
		SecureLayer(QObject *parent = 0, const char *name = 0);

		void setStatefulOnly(bool b);

	protected:
		void layerUpdateBegin();
		void layerUpdateEnd();

	signals:
		void readyRead();
		void readyReadOutgoing();
		void closed();
		void error();

	private:
		bool _signals;
		int _read, _readout;
		bool _closed, _error;
	};

	class QCA_EXPORT TLS : public SecureLayer, public Algorithm
	{
		Q_OBJECT
	public:
		enum Version
		{
			TLS_v1,
			SSL_v3,
			SSL_v2
		};
		enum Error
		{
			ErrHandshake, ///< problem during the negotiation
			ErrCrypt      ///< problem at anytime after
		};
		enum IdentityResult
		{
			Valid,        ///< identity is verified
			HostMismatch, ///< valid cert provided, but wrong owner
			BadCert,      ///< invalid cert
			NoCert        ///< identity unknown
		};

		TLS(QObject *parent = 0, const char *name = 0, const QString &provider = QString());
		~TLS();

		void reset();

		static QStringList supportedCipherSuites(const QString &provider = QString());

		void setCertificate(const CertificateChain &cert, const PrivateKey &key);
		void setStore(const Store &store);
		void setConstraints(SecurityLevel s);
		void setConstraints(int minSSF, int maxSSF);
		void setConstraints(const QStringList &cipherSuiteList);

		static bool canCompress(const QString &provider = QString());
		void setCompressionEnabled(bool b);

		bool startClient(const QString &host = QString());
		bool startServer();

		bool isHandshaken() const;
		bool isCompressed() const;
		Version version() const;
		QString cipherSuite() const;
		int cipherBits() const;
		int cipherMaxBits() const;
		Error errorCode() const;

		IdentityResult peerIdentityResult() const;
		CertValidity peerCertificateValidity() const;
		CertificateChain localCertificateChain() const;
		CertificateChain peerCertificateChain() const;

		// reimplemented
		virtual bool isClosable() const;
		virtual bool haveClosed() const;
		virtual bool haveError() const;
		virtual int bytesAvailable() const;
		virtual int bytesOutgoingAvailable() const;
		virtual void close();
		virtual void write(const QSecureArray &a);
		virtual QSecureArray read();
		virtual void writeIncoming(const QByteArray &a);
		virtual QByteArray readOutgoing(int *plainBytes = 0);
		virtual QSecureArray readUnprocessed();

	signals:
		void handshaken();

	public:
		class Private;
	private:
		friend class Private;
		Private *d;
	};

	class QCA_EXPORT SASL : public SecureLayer, public Algorithm
	{
		Q_OBJECT
	public:
		enum Error
		{
			ErrAuth, ///< problem during the authentication process
			ErrCrypt ///< problem at anytime after
		};
		enum AuthCondition
		{
			NoMech,
			BadProto,
			BadServ,
			BadAuth,
			NoAuthzid,
			TooWeak,
			NeedEncrypt,
			Expired,
			Disabled,
			NoUser,
			RemoteUnavail
		};
		enum AuthFlags
		{
			AllowPlain             = 0x01,
			AllowAnonymous         = 0x02,
			RequireForwardSecrecy  = 0x04,
			RequirePassCredentials = 0x08,
			RequireMutualAuth      = 0x10,
			RequireAuthzidSupport  = 0x20  // server-only
		};

		SASL(QObject *parent = 0, const char *name = 0, const QString &provider = QString());
		~SASL();

		void reset();

		// configuration
		void setConstraints(AuthFlags f, SecurityLevel s = SL_None);
		void setConstraints(AuthFlags f, int minSSF, int maxSSF);
		void setLocalAddr(const QHostAddress &addr, Q_UINT16 port);
		void setRemoteAddr(const QHostAddress &addr, Q_UINT16 port);
		void setExternalAuthId(const QString &authid);
		void setExternalSSF(int);

		// main
		bool startClient(const QString &service, const QString &host, const QStringList &mechlist, bool allowClientSendFirst = true);
		bool startServer(const QString &service, const QString &host, const QString &realm, QStringList *mechlist, bool allowServerSendLast = false);
		void putStep(const QByteArray &stepData);
		void putServerFirstStep(const QString &mech);
		void putServerFirstStep(const QString &mech, const QByteArray &clientInit);
		int ssf() const;
		Error errorCode() const;
		AuthCondition authCondition() const;

		// authentication
		void setUsername(const QString &user);
		void setAuthzid(const QString &auth);
		void setPassword(const QSecureArray &pass);
		void setRealm(const QString &realm);
		void continueAfterParams();
		void continueAfterAuthCheck();

		// reimplemented
		virtual bool haveError() const;
		virtual int bytesAvailable() const;
		virtual int bytesOutgoingAvailable() const;
		virtual void close();
		virtual void write(const QSecureArray &a);
		virtual QSecureArray read();
		virtual void writeIncoming(const QByteArray &a);
		virtual QByteArray readOutgoing(int *plainBytes = 0);

	signals:
		void clientFirstStep(const QString &mech, const QByteArray *clientInit);
		void nextStep(const QByteArray &stepData);
		void needParams(bool user, bool authzid, bool pass, bool realm);
		void authCheck(const QString &user, const QString &authzid);
		void authenticated();

	public:
		class Private;
	private:
		friend class Private;
		Private *d;
	};
}

#endif
