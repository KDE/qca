/*
 * qca.h - Qt Cryptographic Architecture
 * Copyright (C) 2003  Justin Karneges
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

#ifndef QCA_H
#define QCA_H

#include<qstring.h>
#include<qcstring.h>
#include<qdatetime.h>
#include<qmap.h>
#include<qptrlist.h>
#include<qobject.h>

#ifdef Q_OS_WIN32
#  ifndef QCA_STATIC
#    ifdef QCA_MAKEDLL
#      define QCA_EXPORT __declspec(dllexport)
#    else
#      define QCA_EXPORT __declspec(dllimport)
#    endif
#  endif
#endif
#ifndef QCA_EXPORT
#define QCA_EXPORT
#endif

#ifdef Q_OS_WIN32
#  ifdef QCA_PLUGIN_DLL
#    define QCA_PLUGIN_EXPORT extern "C" __declspec(dllexport)
#  else
#    define QCA_PLUGIN_EXPORT extern "C" __declspec(dllimport)
#  endif
#endif
#ifndef QCA_PLUGIN_EXPORT
#define QCA_PLUGIN_EXPORT extern "C"
#endif

class QHostAddress;
class QStringList;

class QCAProvider;
class QCA_HashContext;
class QCA_CipherContext;
class QCA_CertContext;

namespace QCA
{
	enum {
		CAP_SHA1      = 0x0001,
		CAP_SHA256    = 0x0002,
		CAP_MD5       = 0x0004,
		CAP_BlowFish  = 0x0008,
		CAP_TripleDES = 0x0010,
		CAP_AES128    = 0x0020,
		CAP_AES256    = 0x0040,
		CAP_RSA       = 0x0080,
		CAP_X509      = 0x0100,
		CAP_TLS       = 0x0200,
		CAP_SASL      = 0x0400
	};

	enum {
		CBC = 0x0001,
		CFB = 0x0002
	};

	enum {
		Encrypt = 0x0001,
		Decrypt = 0x0002
	};

	QCA_EXPORT void init();
	QCA_EXPORT bool isSupported(int capabilities);
	QCA_EXPORT void insertProvider(QCAProvider *);
	QCA_EXPORT void unloadAllPlugins();

	QCA_EXPORT QString arrayToHex(const QByteArray &);
	QCA_EXPORT QByteArray hexToArray(const QString &);

	class QCA_EXPORT Hash
	{
	public:
		Hash(const Hash &);
		Hash & operator=(const Hash &);
		~Hash();

		void clear();
		void update(const QByteArray &a);
		QByteArray final();

	protected:
		Hash(QCA_HashContext *);

	private:
		class Private;
		Private *d;
	};

	template <class T>
	class QCA_EXPORT HashStatic
	{
	public:
		HashStatic<T>() {}

		static QByteArray hash(const QByteArray &a)
		{
			T obj;
			obj.update(a);
			return obj.final();
		}

		static QByteArray hash(const QCString &cs)
		{
			QByteArray a(cs.length());
			memcpy(a.data(), cs.data(), a.size());
			return hash(a);
		}

		static QString hashToString(const QByteArray &a)
		{
			return arrayToHex(hash(a));
		}

		static QString hashToString(const QCString &cs)
		{
			return arrayToHex(hash(cs));
		}
	};

	class QCA_EXPORT Cipher
	{
	public:
		Cipher(const Cipher &);
		Cipher & operator=(const Cipher &);
		~Cipher();

		QByteArray dyn_generateKey(int size=-1) const;
		QByteArray dyn_generateIV() const;
		void reset(int dir, int mode, const QByteArray &key, const QByteArray &iv, bool pad=true);
		bool update(const QByteArray &a);
		QByteArray final(bool *ok=0);

	protected:
		Cipher(QCA_CipherContext *, int dir, int mode, const QByteArray &key, const QByteArray &iv, bool pad);

	private:
		class Private;
		Private *d;
	};

	template <class T>
	class QCA_EXPORT CipherStatic
	{
	public:
		CipherStatic<T>() {}

		static QByteArray generateKey(int size=-1)
		{
			T obj;
			return obj.dyn_generateKey(size);
		}

		static QByteArray generateIV()
		{
			T obj;
			return obj.dyn_generateIV();
		}
	};

	class QCA_EXPORT SHA1 : public Hash, public HashStatic<SHA1>
	{
	public:
		SHA1();
	};

	class QCA_EXPORT SHA256 : public Hash, public HashStatic<SHA256>
	{
	public:
		SHA256();
	};

	class QCA_EXPORT MD5 : public Hash, public HashStatic<MD5>
	{
	public:
		MD5();
	};

	class QCA_EXPORT BlowFish : public Cipher, public CipherStatic<BlowFish>
	{
	public:
		BlowFish(int dir=Encrypt, int mode=CBC, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray(), bool pad=true);
	};

	class QCA_EXPORT TripleDES : public Cipher, public CipherStatic<TripleDES>
	{
	public:
		TripleDES(int dir=Encrypt, int mode=CBC, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray(), bool pad=true);
	};

	class QCA_EXPORT AES128 : public Cipher, public CipherStatic<AES128>
	{
	public:
		AES128(int dir=Encrypt, int mode=CBC, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray(), bool pad=true);
	};

	class QCA_EXPORT AES256 : public Cipher, public CipherStatic<AES256>
	{
	public:
		AES256(int dir=Encrypt, int mode=CBC, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray(), bool pad=true);
	};

	class RSA;
	class QCA_EXPORT RSAKey
	{
	public:
		RSAKey();
		RSAKey(const RSAKey &from);
		RSAKey & operator=(const RSAKey &from);
		~RSAKey();

		bool isNull() const;
		bool havePublic() const;
		bool havePrivate() const;

		QByteArray toDER(bool publicOnly=false) const;
		bool fromDER(const QByteArray &a);

		QString toPEM(bool publicOnly=false) const;
		bool fromPEM(const QString &);

		// only call if you know what you are doing
		bool fromNative(void *);

	private:
		class Private;
		Private *d;

		friend class RSA;
		friend class TLS;
		bool encrypt(const QByteArray &a, QByteArray *out, bool oaep) const;
		bool decrypt(const QByteArray &a, QByteArray *out, bool oaep) const;
		bool generate(unsigned int bits);
	};

	class QCA_EXPORT RSA
	{
	public:
		RSA();
		~RSA();

		RSAKey key() const;
		void setKey(const RSAKey &);

		bool encrypt(const QByteArray &a, QByteArray *out, bool oaep=false) const;
		bool decrypt(const QByteArray &a, QByteArray *out, bool oaep=false) const;

		static RSAKey generateKey(unsigned int bits);

	private:
		RSAKey v_key;
	};

	typedef QMap<QString, QString> CertProperties;
	class QCA_EXPORT Cert
	{
	public:
		Cert();
		Cert(const Cert &);
		Cert & operator=(const Cert &);
		~Cert();

		bool isNull() const;

		QString commonName() const;
		QString serialNumber() const;
		QString subjectString() const;
		QString issuerString() const;
		CertProperties subject() const;
		CertProperties issuer() const;
		QDateTime notBefore() const;
		QDateTime notAfter() const;

		QByteArray toDER() const;
		bool fromDER(const QByteArray &a);

		QString toPEM() const;
		bool fromPEM(const QString &);

	private:
		class Private;
		Private *d;

		friend class TLS;
		void fromContext(QCA_CertContext *);
	};

	class QCA_EXPORT TLS : public QObject
	{
		Q_OBJECT
	public:
		enum Validity {
			NoCert,
			Valid,
			HostMismatch,
			Rejected,
			Untrusted,
			SignatureFailed,
			InvalidCA,
			InvalidPurpose,
			SelfSigned,
			Revoked,
			PathLengthExceeded,
			Expired,
			Unknown
		};
		enum Error { ErrHandshake, ErrCrypt };

		TLS(QObject *parent=0);
		~TLS();

		void setCertificate(const Cert &cert, const RSAKey &key);
		void setCertificateStore(const QPtrList<Cert> &store);  // note: store must persist

		void reset();
		bool startClient(const QString &host="");
		bool startServer();
		void close();
		bool isHandshaken() const;

		// plain (application side)
		void write(const QByteArray &a);
		QByteArray read();

		// encoded (socket side)
		void writeIncoming(const QByteArray &a);
		QByteArray readOutgoing();
		QByteArray readUnprocessed();

		// cert related
		const Cert & peerCertificate() const;
		int certificateValidityResult() const;

	signals:
		void handshaken();
		void readyRead();
		void readyReadOutgoing(int plainBytes);
		void closed();
		void error(int);

	private slots:
		void update();

	private:
		class Private;
		Private *d;
	};

	class QCA_EXPORT SASL : public QObject
	{
		Q_OBJECT
	public:
		enum Error { ErrAuth, ErrCrypt };
		enum ErrorCond {
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
		SASL(QObject *parent=0);
		~SASL();

		static void setAppName(const QString &name);

		void reset();
		int errorCondition() const;

		// options
		void setAllowPlain(bool);
		void setAllowAnonymous(bool);
		void setAllowActiveVulnerable(bool);
		void setAllowDictionaryVulnerable(bool);
		void setRequireForwardSecrecy(bool);
		void setRequirePassCredentials(bool);
		void setRequireMutualAuth(bool);

		void setMinimumSSF(int);
		void setMaximumSSF(int);
		void setExternalAuthID(const QString &authid);
		void setExternalSSF(int);

		void setLocalAddr(const QHostAddress &addr, Q_UINT16 port);
		void setRemoteAddr(const QHostAddress &addr, Q_UINT16 port);

		// initialize
		bool startClient(const QString &service, const QString &host, const QStringList &mechlist, bool allowClientSendFirst=true);
		bool startServer(const QString &service, const QString &host, const QString &realm, QStringList *mechlist);

		// authentication
		void putStep(const QByteArray &stepData);
		void putServerFirstStep(const QString &mech);
		void putServerFirstStep(const QString &mech, const QByteArray &clientInit);
		void setUsername(const QString &user);
		void setAuthzid(const QString &auth);
		void setPassword(const QString &pass);
		void setRealm(const QString &realm);
		void continueAfterParams();
		void continueAfterAuthCheck();

		// security layer
		int ssf() const;
		void write(const QByteArray &a);
		QByteArray read();
		void writeIncoming(const QByteArray &a);
		QByteArray readOutgoing();

	signals:
		// for authentication
		void clientFirstStep(const QString &mech, const QByteArray *clientInit);
		void nextStep(const QByteArray &stepData);
		void needParams(bool user, bool authzid, bool pass, bool realm);
		void authCheck(const QString &user, const QString &authzid);
		void authenticated();

		// for security layer
		void readyRead();
		void readyReadOutgoing(int plainBytes);

		// error
		void error(int);

	private slots:
		void tryAgain();

	private:
		class Private;
		Private *d;

		void handleServerFirstStep(int r);
	};
};

#endif
