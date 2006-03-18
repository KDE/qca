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

	/**
	   Generic interface to a security layer
	*/
	class QCA_EXPORT SecureLayer : public QObject
	{
		Q_OBJECT
	public:
		SecureLayer(QObject *parent = 0);

		virtual bool isClosable() const;
		virtual int bytesAvailable() const = 0;
		virtual int bytesOutgoingAvailable() const = 0;
		virtual void close();

		// plain (application side)
		virtual void write(const QByteArray &a) = 0;
		virtual QByteArray read() = 0;

		// encoded (network side)
		virtual void writeIncoming(const QByteArray &a) = 0;
		virtual QByteArray readOutgoing(int *plainBytes = 0) = 0;
		virtual QByteArray readUnprocessed();

	signals:
		void readyRead();
		void readyReadOutgoing();
		void closed();
		void error();
	};

	/**
	   Transport Layer Security / Secure Socket Layer 
	*/
	class QCA_EXPORT TLS : public SecureLayer, public Algorithm
	{
		Q_OBJECT
	public:
		/**
		   Operating mode
		*/
		enum Mode
		{
			Stream,  ///< stream mode
			Datagram ///< datagram mode
		};

		/**
		   Version of %TLS or SSL
		*/
		enum Version
		{
			TLS_v1, ///< Transport Layer Security, version 1
			SSL_v3, ///< Secure Socket Layer, version 3
			SSL_v2, ///< Secure Socket Layer, version 2
			DTLS_v1 ///< Datagram Transport Layer Security, version 1
		};

		/**
		   Type of error
		*/
		enum Error
		{
			ErrorInit,      ///< problem starting up %TLS
			ErrorHandshake, ///< problem during the negotiation
			ErrorCrypt      ///< problem at anytime after
		};

		/**
		   Type of identity
		*/
		enum IdentityResult
		{
			Valid,              ///< identity is verified
			HostMismatch,       ///< valid cert provided, but wrong owner
			InvalidCertificate, ///< invalid cert
			NoCertificate       ///< identity unknown
		};

		/** 
		    Constructor for Transport Layer Security connection

		    This produces a Stream (normal %TLS) rather than Datagram (DTLS) object.
		    If you want to do DTLS, see below.
		    
		    \param parent the parent object for this object
		    \param provider the name of the provider, if a specific provider is required
		*/
		TLS(QObject *parent = 0, const QString &provider = QString());

		/**
		   Constructor for Transport Layer Security connection
		   
		   \param mode the connection Mode
		   \param parent the parent object for this object
		   \param provider the name of the provider, if a specific provider is required
		*/
		TLS(Mode mode, QObject *parent = 0, const QString &provider = QString());

		~TLS();

		void reset();

		/**
		   Get the list of Cipher Suites that a provider can use.

		   A cipher suite is a combination of key exchange, encryption and hashing
		   algorithms that are agreed during the initial handshake between client
		   and server.

		   \param version the protocol Version that the cipher suites are required for
		   \param provider the provider to check, if a particular provider is required.

		   \note If you don't specify a provider, one will be picked based on the
		   provider priority system. You will not get the list of cipher suites supported
		   by all providers unless you call this function on all providers.

		   \return list of the the names of the cipher suites supported.
		*/
		static QStringList supportedCipherSuites(const Version &version = TLS_v1, const QString &provider = QString());

		void setCertificate(const CertificateChain &cert, const PrivateKey &key);

		/**
		   Set up the set of trusted certificates that will be used to verify
		   that the certificate provided is valid.

		   Typically, this will be the collection of root certificates from the system,
		   which you can get using QCA::systemStore(), however you may choose to pass
		   whatever certificates match your assurance needs.

		   \param trusted a bundle of trusted certificates.
		*/
		void setTrustedCertificates(const CertificateCollection &trusted);
		void setConstraints(SecurityLevel s);
		void setConstraints(int minSSF, int maxSSF);
		void setConstraints(const QStringList &cipherSuiteList);

		/**
		   test if the link can be compressed

		   \param mode the Mode to use
		   \param provider the provider to use, if a specific provider is required

		   \return true if the link can use compression
		*/
		static bool canCompress(Mode mode = Stream, const QString &provider = QString());

		/**
		   set the link to use compression

		   \param b true if the link should use compression, or false to disable compression
		*/
		void setCompressionEnabled(bool b);

		void startClient(const QString &host = QString());
		void startServer();

		/**
		   test if the handshake is complete

		   \return true if the handshake is complete

		   \sa handshaken
		*/
		bool isHandshaken() const;

		/**
		   test if the link is compressed

		   \return true if the link is compressed
		*/
		bool isCompressed() const;

		/**
		   The protocol version
		*/
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
		virtual int bytesAvailable() const;
		virtual int bytesOutgoingAvailable() const;
		virtual void close();
		virtual void write(const QByteArray &a);
		virtual QByteArray read();
		virtual void writeIncoming(const QByteArray &a);
		virtual QByteArray readOutgoing(int *plainBytes = 0);
		virtual QByteArray readUnprocessed();

		// for DTLS
		int packetsAvailable() const;
		int packetsOutgoingAvailable() const;
		void setPacketMTU(int size) const;

	signals:
		/**
		   Emitted when the protocol handshake is complete

		   \sa isHandshaken
		*/
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
			ErrorInit,      ///< problem starting up SASL
			ErrorHandshake, ///< problem during the authentication process
			ErrorCrypt      ///< problem at anytime after
		};

		/**
		   Possible authentication error states
		*/
		enum AuthCondition
		{
			AuthFail,     ///< Generic authentication failure
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
			RemoteUnavail ///< Remote service needed for auth is gone (server side only)
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

		/**
		   Parameter status for the SASL authentication

		   This is used to track which parameters are currently held
		*/
		class Params
		{
		public:
			/**
			   User is held
			*/
			bool user;

			/**
			   Authorization ID is held
			*/
			bool authzid;

			/**
			   Password is held
			*/
			bool pass;

			/**
			   Realm is held
			*/
			bool realm;
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

		/**
		   Reset the SASL mechanism
		*/
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
		   Specify the id of the externally secured connection

		   \param authid the id of the connection
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

		   startClient must be called on the client side of the connection.
		   clientStarted will be emitted when the operation is completed.

		   \param service the name of the service
		   \param host the client side host name
		   \param mechlist the list of mechanisms which can be used
		   \param ClientSendMode the mode to use on the client side
		*/
		void startClient(const QString &service, const QString &host, const QStringList &mechlist, enum ClientSendMode = AllowClientSendFirst);

		/**
		   Initialise the server side of the connection

		   startServer must be called on the server side of the connection.
		   serverStarted will be emitted when the operation is completed.

		   \param service the name of the service
		   \param host the server side host name
		   \param realm the realm to use
		   \param ServerSendMode which mode to use on the server side
		*/
		void startServer(const QString &service, const QString &host, const QString &realm, enum ServerSendMode = DisableServerSendLast);

		/**
		   Process the first step in server mode (server)

		   Call this with the mechanism selected by the client.  If there
		   is initial client data, call the other version of this function
		   instead.
		*/
		void putServerFirstStep(const QString &mech);

		/**
		   Process the first step in server mode (server)

		   Call this with the mechanism selected by the client, and initial
		   client data.  If there is no initial client data, call the other
		   version of this function instead.
		*/
		void putServerFirstStep(const QString &mech, const QByteArray &clientInit);

		/**
		   Process an authentication step

		   Call this with authentication data received from the network.
		   The only exception is the first step in server mode, in which
		   case putServerFirstStep must be called.
		*/
		void putStep(const QByteArray &stepData);

		/**
		   Return the mechanism selected (client)
		*/
		QString mechanism() const;

		/**
		   Return the mechanism list (server)
		*/
		QStringList mechanismList() const;

		/**
		   Return the security strength factor of the connection
		*/
		int ssf() const;

		/**
		   Return the error code
		*/
		Error errorCode() const;

		/**
		   Return the reason for authentication failure
		*/
		AuthCondition authCondition() const;

		// authentication
		/**
		   Specify the username to use in authentication

		   \param user the username to use
		*/
		void setUsername(const QString &user);

		/**
		   Specify the authorization identity to use in authentication

		   \param auth the authorization identity to use
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
		   Continue negotiation after parameters have been set (client)
		*/
		void continueAfterParams();

		/**
		   Continue negotiation after auth ids have been checked (server)
		*/
		void continueAfterAuthCheck();

		// reimplemented

		/**
		   test how many (if any) bytes are available
		*/
		virtual int bytesAvailable() const;

		/**
		   test how many bytes (if any) are available
		*/
		virtual int bytesOutgoingAvailable() const;

		virtual void write(const QByteArray &a);
		virtual QByteArray read();

		virtual void writeIncoming(const QByteArray &a);
		virtual QByteArray readOutgoing(int *plainBytes = 0);

	signals:
		void clientStarted(bool clientInit, const QByteArray &clientInitData); // (client)
		void serverStarted(); // (server)
		void nextStep(const QByteArray &stepData);
		void needParams(const Params &params); // (client)
		void authCheck(const QString &user, const QString &authzid); // (server)
		void authenticated();

	private:
		class Private;
		friend class Private;
		Private *d;
	};
}

#endif
