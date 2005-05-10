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

#include <QObject>
#include "qca_core.h"
#include "qca_publickey.h"
#include "qca_cert.h"

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
	// writeIncoming: call haveClosed/ok, read, and readOutgoing
	// close: call haveClosed/ok and readOutgoing
	// haveClosed: if Closed, call readUnprocessed
	class QCA_EXPORT SecureFilter
	{
	public:
		virtual ~SecureFilter();

		virtual bool isClosable() const;
		virtual bool haveClosed() const;
		virtual bool ok() const = 0;
		virtual int bytesAvailable() const = 0;
		virtual int bytesOutgoingAvailable() const = 0;
		virtual void close();

		// plain (application side)
		virtual void write(const QSecureArray &a) = 0;
		virtual QSecureArray read() = 0;

		// encoded (network side)
		virtual void writeIncoming(const QByteArray &a) = 0;
		virtual QByteArray readOutgoing(int *plainBytes = 0) = 0;
		virtual QByteArray readUnprocessed();
	};

	// securelayer - "nicer" interface, using signals.  subclass
	//  should call layerUpdateBegin/End before and after write,
	//  writeIncoming, or close.
	class QCA_EXPORT SecureLayer : public QObject, public SecureFilter
	{
		Q_OBJECT
	public:
		SecureLayer(QObject *parent = 0);

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
			ErrorHandshake, ///< problem during the negotiation
			ErrorCrypt      ///< problem at anytime after
		};
		enum IdentityResult
		{
			Valid,              ///< identity is verified
			HostMismatch,       ///< valid cert provided, but wrong owner
			InvalidCertificate, ///< invalid cert
			NoCertificate       ///< identity unknown
		};

		TLS(QObject *parent = 0, const QString &provider = QString());
		~TLS();

		void reset();

		static QStringList supportedCipherSuites(const QString &provider = QString());

		void setCertificate(const CertificateChain &cert, const PrivateKey &key);
		void setTrustedCertificates(const CertificateCollection &trusted);
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
		Validity peerCertificateValidity() const;
		CertificateChain localCertificateChain() const;
		CertificateChain peerCertificateChain() const;

		// reimplemented
		virtual bool isClosable() const;
		virtual bool haveClosed() const;
		virtual bool ok() const;
		virtual int bytesAvailable() const;
		virtual int bytesOutgoingAvailable() const;
		virtual void close();
		virtual void write(const QSecureArray &a);
		virtual QSecureArray read();
		virtual void writeIncoming(const QByteArray &a);
		virtual QByteArray readOutgoing(int *plainBytes = 0);
		virtual QByteArray readUnprocessed();

	signals:
		void handshaken();

	private:
		class Private;
		friend class Private;
		Private *d;
	};

	/**
	   Simple Authentication and Security Layer protocol implementation

	   This class implements the Simple Authenication and Security Layer protocol,
	   which is described in RFC2222 - see <a href="http://www.ietf.org/rfc/rfc2222.txt">
	   http://www.ietf.org/rfc/rfc2222.txt</a>.

	   As the name suggests, %SASL provides authentication (eg, a "login" of some form), for
	   a connection oriented protocol, and can also provide protection for the subsequent
	   connection.

	   The %SASL protocol is designed to be extensible, through a range of "mechanisms", where
	   a mechanism is the actual authentication method. Example mechanisms include Anonymous,
	   LOGIN, Kerberos V4, and GSSAPI. Mechanisms can be added (potentially without restarting
	   the server application) by the system administrator.

	   It is important to understand that %SASL is neither "network aware" nor "protocol aware".
	   That means that %SASL does not understand how the client connects to the server, and %SASL
	   does not understand the actual application protocol.
	*/
	class QCA_EXPORT SASL : public SecureLayer, public Algorithm
	{
		Q_OBJECT
	public:
		/**
		   Possible errors that may occur when using SASL
		*/
		enum Error
		{
			ErrAuth, ///< problem during the authentication process
			ErrCrypt ///< problem at anytime after
		};

		/**
		   Possible authentication error states

These don't appear to map:
SASL_FAIL      (-1)  generic failure
SASL_NOMEM     (-2)  memory shortage failure
SASL_BUFOVER   (-3)  overflowed buffer
SASL_NOTDONE   (-6)  can't request info until later in exchange
SASL_BADPARAM  (-7)  invalid parameter supplied
SASL_TRYAGAIN  (-8)  transient failure (e.g., weak key)
SASL_BADMAC    (-9)  integrity check failed
                             -- client only codes --
SASL_INTERACT   (2)  needs user interaction
SASL_WRONGMECH (-11) mechanism doesn't support requested feature
SASL_NEWSECRET (-12) new secret needed
                              -- server only codes --
SASL_TRANS     (-17) One time use of a plaintext password will
                                enable requested mechanism for user
SASL_PWLOCK    (-21) password locked
SASL_NOCHANGE  (-22) requested change was not needed
SASL_BADVERS   (-23) version mismatch with plug-in

SASL_NOPATH    (-25) path not set
		*/
		enum AuthCondition
		{
			NoMech,       ///< No compatible/appropriate authentication mechanism
			BadProto,     ///< Bad protocol or cancelled
			BadServ,      ///< Server failed mutual authentication (client side only)
			BadAuth,      ///< Authentication failure (server side only)
			NoAuthzid,    ///< Authorization failure (server side only)
			TooWeak,      ///< Mechanism too weak for this user (server side only)
			NeedEncrypt,  ///< Encryption is needed in order to use mechanism (server side only)
			Expired,      ///< Passphrase expired, has to be reset (server side only)
			Disabled,     ///< Account is disabled (server side only)
			NoUser,       ///< User not found (server side only)
			RemoteUnavail
		};


		/**
		   Authentication requirement flag values
		*/
		enum AuthFlags
		{
			AllowPlain             = 0x01,
			AllowAnonymous         = 0x02,
			RequireForwardSecrecy  = 0x04,
			RequirePassCredentials = 0x08,
			RequireMutualAuth      = 0x10,
			RequireAuthzidSupport  = 0x20  // server-only
		};

		/**
		   Mode options for client side sending
		*/
		enum ClientSendMode
		{
			AllowClientSendFirst,
			DisableClientSendFirst
		};

		/**
		   Mode options for server side sending
		*/
		enum ServerSendMode
		{
			AllowServerSendLast,
			DisableServerSendLast
		};

		class Params
		{
		public:
			bool user, authzid, pass, realm;
		};

		/**
		   Standard constructor

		   \param parent the parent object for this SASL connection
		   \param provider if specified, the provider to use. If not 
		   specified, or specified as empty, then any provider is 
		   acceptable.
		*/
		SASL(QObject *parent = 0, const QString &provider = QString());
		~SASL();

		void reset();

		// configuration
		/**
		   Specify connection constraints

		   SASL supports a range of authentication requirements, and
		   a range of security levels. This method allows you to
		   specify the requirements for your connection.

		   \param f the authentication requirements, which you typically
		   build using a binary OR function (eg AllowPlain | AllowAnonymous)
		   \param s the security level of the encryption, if used. See
		   SecurityLevel for details of what each level provides.
		*/
		void setConstraints(AuthFlags f, SecurityLevel s = SL_None);

		/**
		   \overload

		   Unless you have a specific reason for directly specifying a strength
		   factor, you probably should use the method above.

		   \param f the authentication requirements, which you typically
		   build using a binary OR function (eg AllowPlain | AllowAnonymous)
		   \param minSSF the minimum security strength factor that is required
		   \param maxSSF the maximum security strength factor that is required

		   \note Security strength factors are a rough approximation to key
		   length in the encryption function (eg if you are securing with plain
		   DES, the security strength factor would be 56).
		*/
		void setConstraints(AuthFlags f, int minSSF, int maxSSF);

		/**
		   Specify the local address.
		   
		   \param addr the address of the local part of the connection
		   \param port the port number of the local part of the connection
		*/
		void setLocalAddr(const QString &addr, quint16 port);

		/**
		   Specify the peer address.

		   \param addr the address of the peer side of the connection
		   \param port the port number of the peer side of the connection
		*/
		void setRemoteAddr(const QString &addr, quint16 port);

		/**
		   FIXME: Justin to complete
		   
		*/
		void setExternalAuthId(const QString &authid);

		/**
		   Specify a security strength factor for an externally secured connection

		   \param strength the security strength factor of the connection
		*/
		void setExternalSSF(int strength);

		// main
		/**
		   Initialise the client side of the connection

		   startClient must be called on the client side of the connection

		   \param service the name of the service
		   \param host the client side host name
		   \param mechlist the list of mechanisms which can be used
		   \param ClientSendMode the mode to use on the client side
		*/
		bool startClient(const QString &service, const QString &host, const QStringList &mechlist, enum ClientSendMode = AllowClientSendFirst);

		/**
		   Initialise the server side of the connection

		   startServer must be called on the server side of the connection.

		   \param service the name of the service
		   \param host the server side host name
		   \param realm the realm to use
		   \param mechlist the list of available mechanisms
		   \param ServerSendMode which mode to use on the server side
		*/
		bool startServer(const QString &service, const QString &host, const QString &realm, QStringList *mechlist, enum ServerSendMode = DisableServerSendLast);

		/**
		   FIXME: Justin to complete
		   
		*/
		void putStep(const QByteArray &stepData);

		/**
		   FIXME: Justin to complete
		   
		*/
		void putServerFirstStep(const QString &mech);

		/**
		   FIXME: Justin to complete
		   
		*/
		void putServerFirstStep(const QString &mech, const QByteArray &clientInit);

		/**
		   Return the security strength factor of the connection
		*/
		int ssf() const;
		Error errorCode() const;
		AuthCondition authCondition() const;

		// authentication
		/**
		   Specify the username to use in authentication

		   \param user the username to use
		*/
		void setUsername(const QString &user);

		/**
		   Specify the authorisation identity to use in authentication

		   \param auth the authorisation identity to use
		*/
		void setAuthzid(const QString &auth);

		/**
		   Specify the password to use in authentication

		   \param pass the password to use
		*/
		void setPassword(const QSecureArray &pass);

		/**
		   Specify the realm to use in authentication

		   \param realm the realm to use
		*/
		void setRealm(const QString &realm);

		/**
		   FIXME: Justin to complete
		   
		*/
		void continueAfterParams();

		/**
		   FIXME: Justin to complete
		   
		*/
		void continueAfterAuthCheck();

		// reimplemented

		/**
		   FIXME: Justin to complete
		   
		*/
		virtual bool ok() const;

		/**
		   test how many (if any) bytes are available
		*/
		virtual int bytesAvailable() const;

		/**
		   test how many bytes (if any) are available
		*/
		virtual int bytesOutgoingAvailable() const;

		/**
		   Close the current SASL connection
		*/
		virtual void close();
		virtual void write(const QSecureArray &a);
		virtual QSecureArray read();

		virtual void writeIncoming(const QByteArray &a);
		virtual QByteArray readOutgoing(int *plainBytes = 0);

	signals:
		void clientFirstStep(const QString &mech, const QByteArray *clientInit);
		void nextStep(const QByteArray &stepData);
		void needParams(const Params &params);
		void authCheck(const QString &user, const QString &authzid);
		void authenticated();

	private:
		class Private;
		friend class Private;
		Private *d;
	};
}

#endif
