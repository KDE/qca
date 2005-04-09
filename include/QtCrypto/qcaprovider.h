/*
 * qcaprovider.h - QCA Plugin API
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

#ifndef QCAPROVIDER_H
#define QCAPROVIDER_H

#include <QtCore>
#include "qca_core.h"
#include "qca_basic.h"
#include "qca_publickey.h"
#include "qca_cert.h"
#include "qca_keystore.h"

#include <limits>

#define QCA_PLUGIN_VERSION 2

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

class QCAPlugin : public QObject
{
	Q_OBJECT
public:
	virtual int version() const = 0;
	virtual QCA::Provider *createProvider() = 0;
};

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
	virtual void setup(Direction dir, const SymmetricKey &key, const InitializationVector &iv) = 0;
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

class KDFContext : public Provider::Context
{
public:
	KDFContext(Provider *p, const QString &type) : Provider::Context(p, type) {}
	virtual SymmetricKey makeKey(const QSecureArray &secret, const InitializationVector &salt, unsigned int keyLength, unsigned int iterationCount) = 0;
};

class DLGroupContext : public QObject, public Provider::Context
{
	Q_OBJECT
public:
	DLGroupContext(Provider *p) : Provider::Context(p, "dlgroup") {}
	virtual QList<DLGroupSet> supportedGroupSets() const = 0;
	virtual bool isNull() const = 0;
	virtual void fetchGroup(DLGroupSet set, bool block) = 0;
	virtual void getResult(QBigInteger *p, QBigInteger *q, QBigInteger *g) const = 0;

signals:
	void finished();
};

class PKeyBase : public QObject, public Provider::Context
{
	Q_OBJECT
public:
	PKeyBase(Provider *p, const QString &type) : Provider::Context(p, type) {}
	virtual bool isNull() const = 0;
	virtual bool isPrivate() const = 0;
	virtual void convertToPublic() = 0;
	virtual int bits() const = 0;

	// encrypt/decrypt
	virtual int maximumEncryptSize(EncryptionAlgorithm alg) const;
	virtual QSecureArray encrypt(const QSecureArray &in, EncryptionAlgorithm alg) const;
	virtual bool decrypt(const QSecureArray &in, QSecureArray *out, EncryptionAlgorithm alg) const;

	// sign / verify
	virtual void startSign(SignatureAlgorithm alg, SignatureFormat format);
	virtual void startVerify(SignatureAlgorithm alg, SignatureFormat format);
	virtual void update(const QSecureArray &in);
	virtual QSecureArray endSign();
	virtual bool endVerify(const QSecureArray &sig);

	// key agreement
	virtual SymmetricKey deriveKey(const PKeyBase &theirs) const;

signals:
	void finished();
};

class RSAContext : public PKeyBase
{
	Q_OBJECT
public:
	RSAContext(Provider *p) : PKeyBase(p, "rsa") {}
	virtual void createPrivate(int bits, int exp, bool block) = 0;
	virtual void createPrivate(const QBigInteger &n, const QBigInteger &e, const QBigInteger &p, const QBigInteger &q, const QBigInteger &d) = 0;
	virtual void createPublic(const QBigInteger &n, const QBigInteger &e) = 0;
	virtual QBigInteger n() const = 0;
	virtual QBigInteger e() const = 0;
	virtual QBigInteger p() const = 0;
	virtual QBigInteger q() const = 0;
	virtual QBigInteger d() const = 0;
};

class DSAContext : public PKeyBase
{
	Q_OBJECT
public:
	DSAContext(Provider *p) : PKeyBase(p, "dsa") {}
	virtual void createPrivate(const DLGroup &domain, bool block) = 0;
	virtual void createPrivate(const DLGroup &domain, const QBigInteger &y, const QBigInteger &x) = 0;
	virtual void createPublic(const DLGroup &domain, const QBigInteger &y) = 0;
	virtual DLGroup domain() const = 0;
	virtual QBigInteger y() const = 0;
	virtual QBigInteger x() const = 0;
};

class DHContext : public PKeyBase
{
	Q_OBJECT
public:
	DHContext(Provider *p) : PKeyBase(p, "dh") {}
	virtual void createPrivate(const DLGroup &domain, bool block) = 0;
	virtual void createPrivate(const DLGroup &domain, const QBigInteger &y, const QBigInteger &x) = 0;
	virtual void createPublic(const DLGroup &domain, const QBigInteger &y) = 0;
	virtual DLGroup domain() const = 0;
	virtual QBigInteger y() const = 0;
	virtual QBigInteger x() const = 0;
};

class PKeyContext : public Provider::Context
{
public:
	PKeyContext(Provider *p) : Provider::Context(p, "pkey") {}

	virtual QList<PKey::Type> supportedTypes() const = 0;
	virtual QList<PKey::Type> supportedIOTypes() const = 0;
	virtual QList<PBEAlgorithm> supportedPBEAlgorithms() const = 0;

	virtual PKeyBase *key() = 0;
	virtual const PKeyBase *key() const = 0;
	virtual PKey::Type type() const = 0;
	virtual void setKey(PKeyBase *key) = 0;

	// import / export
	virtual QSecureArray publicToDER() const = 0;
	virtual QString publicToPEM() const = 0;
	virtual ConvertResult publicFromDER(const QSecureArray &a) = 0;
	virtual ConvertResult publicFromPEM(const QString &s) = 0;
	virtual QSecureArray privateToDER(const QSecureArray &passphrase, PBEAlgorithm pbe) const = 0;
	virtual QString privateToPEM(const QSecureArray &passphrase, PBEAlgorithm pbe) const = 0;
	virtual ConvertResult privateFromDER(const QSecureArray &a, const QSecureArray &passphrase) = 0;
	virtual ConvertResult privateFromPEM(const QString &s, const QSecureArray &passphrase) = 0;
};

class CertBase : public Provider::Context
{
public:
	CertBase(Provider *p, const QString &type) : Provider::Context(p, type) {}

	// import / export
	virtual QSecureArray toDER() const = 0;
	virtual QString toPEM() const = 0;
	virtual ConvertResult fromDER(const QSecureArray &a) = 0;
	virtual ConvertResult fromPEM(const QString &s) = 0;
};

class CertContextProps
{
public:
	int version;                     // cert only
	QDateTime start, end;            // cert only
	CertificateInfo subject;
	CertificateInfo issuer;          // cert only
	Constraints constraints;
	QStringList policies;
	QBigInteger serial;              // cert only
	bool isCA;
	bool isSelfSigned;               // cert only
	int pathLimit;
	QSecureArray sig;
	SignatureAlgorithm sigalgo;
	QByteArray subjectId, issuerId;  // cert only
	QString challenge;               // csr only
	CertificateRequestFormat format; // csr only
};

class CRLContextProps
{
public:
	CertificateInfo issuer;
	int number;
	QDateTime thisUpdate, nextUpdate;
	QList<CRLEntry> revoked;
	QSecureArray sig;
	SignatureAlgorithm sigalgo;
	QByteArray issuerId;
};

class CRLContext;

class CertContext : public CertBase
{
public:
	CertContext(Provider *p) : CertBase(p, "cert") {}

	virtual bool createSelfSigned(const CertificateOptions &opts, const PKeyContext &priv) = 0;
	virtual const CertContextProps *props() const = 0;
	virtual PKeyContext *subjectPublicKey() const = 0; // caller must delete

	// ownership of items IS NOT passed
	virtual Validity validate(const QList<CertContext*> &trusted, const QList<CertContext*> &untrusted, const QList<CRLContext *> &crls, UsageMode u) const = 0;
};

class CSRContext : public CertBase
{
public:
	CSRContext(Provider *p) : CertBase(p, "csr") {}

	virtual bool canUseFormat(CertificateRequestFormat f) const = 0;
	virtual bool createRequest(const CertificateOptions &opts, const PKeyContext &priv) = 0;
	virtual const CertContextProps *props() const = 0;
	virtual PKeyContext *subjectPublicKey() const = 0; // caller must delete
	virtual QString toSPKAC() const = 0;
	virtual ConvertResult fromSPKAC(const QString &s) = 0;
};

class CRLContext : public CertBase
{
public:
	CRLContext(Provider *p) : CertBase(p, "crl") {}

	virtual const CRLContextProps *props() const = 0;
};

class CertCollectionContext : public Provider::Context
{
public:
	CertCollectionContext(Provider *p) : Provider::Context(p, "certcollection") {}

	// ownership of items IS NOT passed
	virtual QByteArray toPKCS7(const QList<CertContext*> &certs, const QList<CRLContext*> &crls) const = 0;

	// ownership of items IS passed
	virtual ConvertResult fromPKCS7(const QByteArray &a, QList<CertContext*> *certs, QList<CRLContext*> *crls) const = 0;
};

class CAContext : public Provider::Context
{
public:
	CAContext(Provider *p) : Provider::Context(p, "ca") {}

	virtual void setup(const CertContext &cert, const PKeyContext &priv) = 0;

	// caller must delete all return values here
	virtual CertContext *certificate() const = 0;
	virtual CertContext *signRequest(const CSRContext &req, const QDateTime &notValidAfter) const = 0;
	virtual CertContext *createCertificate(const PKeyContext &pub, const CertificateOptions &opts) const = 0;
	virtual CRLContext *createCRL(const QDateTime &nextUpdate) const = 0;
	virtual CRLContext *updateCRL(const CRLContext &crl, const QList<CRLEntry> &entries, const QDateTime &nextUpdate) const = 0;
};

class PIXContext : public Provider::Context
{
public:
	PIXContext(Provider *p) : Provider::Context(p, "pix") {}

	virtual QByteArray toPKCS12(const QString &name, const QList<const CertContext*> &chain, const PKeyContext &priv, const QSecureArray &passphrase) const = 0;

	// caller must delete
	virtual ConvertResult fromPKCS12(const QByteArray &in, const QSecureArray &passphrase, QString *name, QList<CertContext*> *chain, PKeyContext **priv) const = 0;
};

class KeyStoreEntryContext : public Provider::Context
{
public:
	KeyStoreEntryContext(Provider *p) : Provider::Context(p, "keystoreentry") {}

	virtual KeyStoreEntry::Type type() const = 0;
	virtual QString name() const = 0;
	virtual QString id() const = 0;

	virtual KeyBundle keyBundle() const;
	virtual Certificate certificate() const;
	virtual CRL crl() const;
	virtual PGPKey pgpSecretKey() const;
	virtual PGPKey pgpPublicKey() const;
};

class KeyStoreContext : public QObject, public Provider::Context
{
	Q_OBJECT
public:
	KeyStoreContext(Provider *p) : Provider::Context(p, "keystore") {}

	virtual int contextId() const = 0; // increment for each new context made
	virtual QString deviceId() const = 0;

	virtual KeyStore::Type type() const = 0;
	virtual QString name() const = 0;

	virtual QList<KeyStoreEntryContext*> entryList() const = 0; // caller must delete
	virtual QList<KeyStoreEntry::Type> entryTypes() const = 0;

	virtual bool isReadOnly() const;

	virtual bool writeEntry(const KeyBundle &kb);
	virtual bool writeEntry(const Certificate &cert);
	virtual bool writeEntry(const CRL &crl);
	virtual PGPKey writeEntry(const PGPKey &key);
	virtual bool removeEntry(const QString &id);

	virtual void submitPassphrase(const QSecureArray &passphrase);

signals:
	void updated();
	void needPassphrase();
};

class KeyStoreListContext : public QObject, public Provider::Context
{
	Q_OBJECT
public:
	KeyStoreListContext(Provider *p) : Provider::Context(p, "keystorelist") {}

	virtual QList<KeyStoreContext*> keyStores() const = 0;

signals:
	void updated(KeyStoreListContext *sender);
};

class TLSContext : public Provider::Context
{
public:
	enum Result { Success, Error, Continue };
	TLSContext(Provider *p) : Provider::Context(p, "tls") {}

	virtual void reset() = 0;
	virtual bool startClient(const QList<CertContext*> &trusted, const QList<CRLContext*> &crls, const CertContext &cert, const PKeyContext &key) = 0;
	virtual bool startServer(const QList<CertContext*> &trusted, const QList<CRLContext*> &crls, const CertContext &cert, const PKeyContext &key) = 0;

	virtual int handshake(const QByteArray &in, QByteArray *out) = 0;
	virtual int shutdown(const QByteArray &in, QByteArray *out) = 0;
	virtual bool encode(const QSecureArray &plain, QByteArray *to_net, int *encoded) = 0;
	virtual bool decode(const QByteArray &from_net, QSecureArray *plain, QByteArray *to_net) = 0;
	virtual bool eof() const = 0;
	virtual QSecureArray unprocessed() = 0;

	virtual Validity peerCertificateValidity() const = 0;
	virtual CertContext *peerCertificate() const = 0;
};

class SASLContext : public Provider::Context
{
public:
	struct HostPort
	{
		//QHostAddress addr;
		//Q_UINT16 port;
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
