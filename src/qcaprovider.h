/*
 * qcaprovider.h - QCA Plugin API
 * Copyright (C) 2003,2004  Justin Karneges
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

#ifndef QCAPROVIDER_H
#define QCAPROVIDER_H

#include <qstring.h>
#include <qdatetime.h>
#include <qobject.h>
#include <qhostaddress.h>
#include "qca.h"

#include <limits>

#define QCA_PLUGIN_VERSION 2

#define QCA_EXPORT_PLUGIN(P) \
	QCA_PLUGIN_EXPORT QCA::Provider *createProvider2() { return new P; } \
	QCA_PLUGIN_EXPORT int version() { return QCA_PLUGIN_VERSION; }

/** \page providers Providers

QCA works on the concept of a "provider". There is a limited
internal provider (named "default"), but most of the work is
done in plugin modules.

The logic to selection of a provider is fairly simple. The user can 
specify a provider name - if that name exists, and the provider supports
the requested feature, then the named provider is used. If that
didn't work, then the available plugins are searched (based on a
priority order) for the requested feature. If that doesn't work,
then the default provider is searched for the requested feature.

So the only way to get the default provider is to either have no other support
whatsoever, or to specify the default provider directly (this goes for the
algorithm constructors as well as setGlobalRNG()).
*/

namespace QCA {

class RandomContext : public Provider::Context
{
public:
	RandomContext(Provider *p) : Provider::Context(p, "random") {}
	virtual QSecureArray nextBytes(int size, Random::Quality q) = 0;
};

class HashContext : public Provider::Context
{
public:
	HashContext(Provider *p, const QString &type) : Provider::Context(p, type) {}
	virtual void clear() = 0;
	virtual void update(const QSecureArray &a) = 0;
	virtual QSecureArray final() = 0;
};

class CipherContext : public Provider::Context
{
public:
	enum Mode { CBC, CFB, ECB };
	CipherContext(Provider *p, const QString &type) : Provider::Context(p, type) {}
	virtual void setup(const SymmetricKey &key, Mode m, Direction dir, const InitializationVector &iv) = 0;
	virtual KeyLength keyLength() const = 0;
	virtual unsigned int blockSize() const = 0;

	virtual bool update(const QSecureArray &in, QSecureArray *out) = 0;
	virtual bool final(QSecureArray *out) = 0;
};

class MACContext : public Provider::Context
{
public:
	MACContext(Provider *p, const QString &type) : Provider::Context(p, type) {}
	virtual void setup(const SymmetricKey &key) = 0;
	virtual KeyLength keyLength() const = 0;

	virtual void update(const QSecureArray &in) = 0;
	virtual void final(QSecureArray *out) = 0;
protected:
	KeyLength anyKeyLength() const
	{
		// this is used instead of a default implementation to make sure that
		// provider authors think about it, at least a bit.
		// See Meyers, Effective C++, Effective C++ (2nd Ed), Item 36
		return KeyLength( 0, std::numeric_limits<int>::max(), 1 );
	}


};

class PKeyBase : public Provider::Context
{
public:
	PKeyBase(Provider *p, const QString &type) : Provider::Context(p, type) {}
	virtual bool isNull() const = 0;
	virtual bool isPrivate() const = 0;
	virtual void convertToPublic() = 0;

	// encrypt/decrypt
	virtual int maximumEncryptSize() const;
	virtual QSecureArray encrypt(const QSecureArray &in);
	virtual bool decrypt(const QSecureArray &in, QSecureArray *out);

	// sign / verify
	virtual void startSign();
	virtual void startVerify();
	virtual void update(const QSecureArray &in);
	virtual QSecureArray endSign();
	virtual bool endVerify(const QSecureArray &sig);

	// key agreement
	virtual SymmetricKey deriveKey(const PKeyBase &theirs);
};

class RSAContext : public PKeyBase
{
public:
	RSAContext(Provider *p) : PKeyBase(p, "rsa") {}
	virtual void createPrivate(int bits, int exp, void (*cb)(RSAContext *c)) = 0;
	virtual void createPrivate(const QBigInteger &p, const QBigInteger &q, const QBigInteger &d, const QBigInteger &n, const QBigInteger &e) = 0;
	virtual void createPublic(const QBigInteger &n, const QBigInteger &e) = 0;
	virtual QBigInteger p() const = 0;
	virtual QBigInteger q() const = 0;
	virtual QBigInteger d() const = 0;
	virtual QBigInteger n() const = 0;
	virtual QBigInteger e() const = 0;
};

class DSAContext : public PKeyBase
{
public:
	DSAContext(Provider *p) : PKeyBase(p, "dsa") {}
	virtual void createPrivate(DL_Group group, void (*cb)(DSAContext *c)) = 0;
	virtual void createPrivate(DL_Group group, const QBigInteger &x, const QBigInteger &y) = 0;
	virtual void createPublic(DL_Group group, const QBigInteger &y) = 0;
	virtual DL_Group domain() const = 0;
	virtual QBigInteger x() const = 0;
	virtual QBigInteger y() const = 0;
};

class DHContext : public PKeyBase
{
public:
	DHContext(Provider *p) : PKeyBase(p, "dh") {}
	virtual void createPrivate(DL_Group group, void (*cb)(DHContext *c)) = 0;
	virtual void createPrivate(DL_Group group, const QBigInteger &x, const QBigInteger &y) = 0;
	virtual void createPublic(DL_Group group, const QBigInteger &y) = 0;
	virtual DL_Group domain() const = 0;
	virtual QBigInteger x() const = 0;
	virtual QBigInteger y() const = 0;
};

class PKeyContext : public Provider::Context
{
public:
	enum Type { RSA, DSA, DH };
	enum ConvertResult { Good, ErrDecode, ErrPassphrase };
	PKeyContext(Provider *p) : Provider::Context(p, "pkey") {}

	virtual PKeyBase *key() const = 0;
	virtual Type type() const = 0;
	virtual void setKey(PKeyBase *key) = 0;

	// import / export
	virtual QSecureArray publicToDER() const = 0;
	virtual QString publicToPEM() const = 0;
	virtual ConvertResult publicFromDER(const QSecureArray &a) = 0;
	virtual ConvertResult publicFromPEM(const QString &s) = 0;
	virtual QSecureArray privateToDER(const QString &passphrase) const = 0;
	virtual QString privateToPEM(const QString &passphrase) const = 0;
	virtual ConvertResult privateFromDER(const QSecureArray &a, const QString &passphrase) = 0;
	virtual ConvertResult privateFromPEM(const QString &s, const QString &passphrase) = 0;
};

class CertContext : public Provider::Context
{
public:
	typedef QMap<QString, QString> Info;
	enum ConvertResult { Good, ErrDecode };
	CertContext(Provider *p) : Provider::Context(p, "cert") {}

	virtual int version() const = 0;
	virtual QDateTime notValidBefore() const = 0;
	virtual QDateTime notValidAfter() const = 0;

	virtual Info subjectInfo() const = 0;
	virtual Info issuerInfo() const = 0;

	virtual QString commonName() const = 0;
	virtual QBigInteger serialNumber() const = 0;
	virtual PKeyContext *subjectPublicKey() const = 0;

	// import / export
	virtual QSecureArray toDER() const = 0;
	virtual QString toPEM() const = 0;
	virtual ConvertResult fromDER(const QSecureArray &a) = 0;
	virtual ConvertResult fromPEM(const QString &s) = 0;
};

class CRLContext : public Provider::Context
{
public:
	enum ConvertResult { Good, ErrDecode };
	CRLContext(Provider *p) : Provider::Context(p, "crl") {}

	// import / export
	virtual QSecureArray toDER() const = 0;
	virtual QString toPEM() const = 0;
	virtual ConvertResult fromDER(const QSecureArray &a) = 0;
	virtual ConvertResult fromPEM(const QString &s) = 0;
};

class StoreContext : public Provider::Context
{
public:
	StoreContext(Provider *p) : Provider::Context(p, "store") {}

	virtual void addCertificate(const CertContext &cert, bool trusted) = 0;
	virtual void addCRL(const CRLContext &crl) = 0;
	virtual CertValidity validate(const CertContext &cert, CertUsage u) const = 0;
};

class TLSContext : public Provider::Context
{
public:
	enum Result { Success, Error, Continue };
	TLSContext(Provider *p) : Provider::Context(p, "tls") {}

	virtual void reset() = 0;
	virtual bool startClient(const StoreContext &store, const CertContext &cert, const PKeyContext &key) = 0;
	virtual bool startServer(const StoreContext &store, const CertContext &cert, const PKeyContext &key) = 0;

	virtual int handshake(const QByteArray &in, QByteArray *out) = 0;
	virtual int shutdown(const QByteArray &in, QByteArray *out) = 0;
	virtual bool encode(const QSecureArray &plain, QByteArray *to_net, int *encoded) = 0;
	virtual bool decode(const QByteArray &from_net, QSecureArray *plain, QByteArray *to_net) = 0;
	virtual bool eof() const = 0;
	virtual QSecureArray unprocessed() = 0;

	virtual CertValidity peerCertificateValidity() const = 0;
	virtual CertContext *peerCertificate() const = 0;
};

class SASLContext : public Provider::Context
{
public:
	struct HostPort
	{
		QHostAddress addr;
		Q_UINT16 port;
	};
	struct AuthParams
	{
		bool user, authzid, pass, realm;
	};
	enum Result
	{
		Success,
		Error,
		NeedParams,
		AuthCheck,
		Continue
	};
	enum AuthError
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
	SASLContext(Provider *p) : Provider::Context(p, "sasl") {}

	// common
	virtual void reset() = 0;
	virtual void setCoreProps(const QString &service, const QString &host, HostPort *local, HostPort *remote) = 0;
	virtual void setSecurityProps(bool noPlain, bool noActive, bool noDict, bool noAnon, bool reqForward, bool reqCreds, bool reqMutual, int ssfMin, int ssfMax, const QString &_ext_authid, int _ext_ssf) = 0;
	virtual int security() const = 0;
	virtual AuthError authError() const = 0;

	// init / first step
	virtual bool clientStart(const QStringList &mechlist) = 0;
	virtual int clientFirstStep(bool allowClientSendFirst) = 0;
	virtual bool serverStart(const QString &realm, QStringList *mechlist, const QString &name) = 0;
	virtual int serverFirstStep(const QString &mech, const QByteArray *in) = 0;

	// get / set params
	virtual AuthParams clientParamsNeeded() const = 0;
	virtual void setClientParams(const QString *user, const QString *authzid, const QSecureArray *pass, const QString *realm) = 0;
	virtual QString username() const = 0;
	virtual QString authzid() const = 0;

	// continue steps
	virtual int nextStep(const QByteArray &in) = 0;
	virtual int tryAgain() = 0;

	// results
	virtual QString mech() const = 0;
	virtual const QByteArray *clientInit() const = 0;
	virtual QByteArray result() const = 0;

	// security layer
	virtual bool encode(const QSecureArray &in, QByteArray *out) = 0;
	virtual bool decode(const QByteArray &in, QSecureArray *out) = 0;
};

}

#endif
