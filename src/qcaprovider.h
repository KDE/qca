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

#include <qglobal.h>
#include <qstring.h>
#include <qdatetime.h>
#include <qobject.h>
#include <qhostaddress.h>
#include "qca.h"

#define QCA_PLUGIN_VERSION 1

// v2 contexts
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
	CipherContext(Provider *p, const QString &type) : Provider::Context(p, type) {}
	virtual void setup(const SymmetricKey &key, Mode m, Direction dir, const InitializationVector &iv, bool pad) = 0;
	virtual KeyLength keyLength() const = 0;
	virtual int blockSize() const = 0;

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
	virtual SymmetricKey deriveKey(PKeyBase *theirs);
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

/*class CertContext : public Provider::Context
{
public:
	enum ConvertResult { Good, ErrDecode };
	CertContext(Provider *p) : Provider::Context(p, X_Cert) {}

	virtual int version() const = 0;
	virtual QDateTime notValidBefore() const = 0;
	virtual QDateTime notValidAfter() const = 0;

	virtual Certificate::Info subjectInfo() const = 0;
	virtual Certificate::Info issuerInfo() const = 0;

	virtual QString commonName() const = 0;
	virtual QBigInteger serialNumber() const = 0;
	virtual PublicKey subjectPublicKey() const = 0;

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
	CRLContext(Provider *p) : Provider::Context(p, X_CRL) {}

	// import / export
	virtual QSecureArray toDER() const = 0;
	virtual QString toPEM() const = 0;
	virtual ConvertResult fromDER(const QSecureArray &a) = 0;
	virtual ConvertResult fromPEM(const QString &s) = 0;
};

class StoreContext : public Provider::Context
{
public:
	StoreContext(Provider *p) : Provider::Context(p, X_Store) {}

	virtual void addCertificate(const Certificate &cert, bool trusted) = 0;
	virtual void addCRL(const CRL &crl) = 0;
	virtual CertValidity validate(const Certificate &cert, CertUsage u) const = 0;
};*/

/*class TLSContext : public Provider::Context
{
public:
	enum Result { Success, Error, Continue };
	TLSContext(Provider *p) : Provider::Context(p, F_TLS) {}

	virtual void reset() = 0;
	virtual bool startClient(Store *store, const Certificate &cert, const PrivateKey &key) = 0;
	virtual bool startServer(Store *store, const Certificate &cert, const PrivateKey &key) = 0;

	virtual int handshake(const QByteArray &in, QByteArray *out) = 0;
	virtual int shutdown(const QByteArray &in, QByteArray *out) = 0;
	virtual bool encode(const QByteArray &plain, QByteArray *to_net, int *encoded) = 0;
	virtual bool decode(const QByteArray &from_net, QByteArray *plain, QByteArray *to_net) = 0;
	virtual bool eof() const = 0;
	virtual QByteArray unprocessed() = 0;

	virtual CertValidity peerCertificateValidity() const = 0;
	virtual Certificate peerCertificate() const = 0;
};

struct QCA_SASLHostPort
{
	QHostAddress addr;
	Q_UINT16 port;
};

struct QCA_SASLNeedParams
{
	bool user, authzid, pass, realm;
};

class SASLContext : public Provider::Context
{
public:
	enum Result { Success, Error, NeedParams, AuthCheck, Continue };
	SASLContext(Provider *p) : Provider::Context(p, F_SASL) {}

	// common
	virtual void reset() = 0;
	virtual void setCoreProps(const QString &service, const QString &host, QCA_SASLHostPort *local, QCA_SASLHostPort *remote) = 0;
	virtual void setSecurityProps(bool noPlain, bool noActive, bool noDict, bool noAnon, bool reqForward, bool reqCreds, bool reqMutual, int ssfMin, int ssfMax, const QString &_ext_authid, int _ext_ssf) = 0;
	virtual int security() const = 0;
	virtual SASL::AuthCond authCond() const = 0;

	// init / first step
	virtual bool clientStart(const QStringList &mechlist) = 0;
	virtual int clientFirstStep(bool allowClientSendFirst) = 0;
	virtual bool serverStart(const QString &realm, QStringList *mechlist, const QString &name) = 0;
	virtual int serverFirstStep(const QString &mech, const QByteArray *in) = 0;

	// get / set params
	virtual QCA_SASLNeedParams clientParamsNeeded() const = 0;
	virtual void setClientParams(const QString *user, const QString *authzid, const QString *pass, const QString *realm) = 0;
	virtual QString username() const=0;
	virtual QString authzid() const=0;

	// continue steps
	virtual int nextStep(const QByteArray &in) = 0;
	virtual int tryAgain() = 0;

	// results
	virtual QString mech() const = 0;
	virtual const QByteArray *clientInit() const = 0;
	virtual QByteArray result() const = 0;

	// security layer
	virtual bool encode(const QByteArray &in, QByteArray *out) = 0;
	virtual bool decode(const QByteArray &in, QByteArray *out) = 0;
};*/

}

// older v1 contexts
class QCAProvider
{
public:
	QCAProvider() {}
	virtual ~QCAProvider() {}

	virtual void init()=0;
	virtual int qcaVersion() const=0;
	virtual int capabilities() const=0;
	virtual void *context(int cap)=0;
};

class QCA_HashContext
{
public:
	virtual ~QCA_HashContext() {}

	virtual QCA_HashContext *clone()=0;
	virtual void reset()=0;
	virtual void update(const char *in, unsigned int len)=0;
	virtual void final(QByteArray *out)=0;
};

class QCA_CipherContext
{
public:
	virtual ~QCA_CipherContext() {}

	virtual QCA_CipherContext *clone()=0;
	virtual int keySize()=0;
	virtual int blockSize()=0;
	virtual bool generateKey(char *out, int keysize=-1)=0;
	virtual bool generateIV(char *out)=0;

	virtual bool setup(int dir, int mode, const char *key, int keysize, const char *iv, bool pad)=0;
	virtual bool update(const char *in, unsigned int len)=0;
	virtual bool final(QByteArray *out)=0;
};

class QCA_RSAKeyContext
{
public:
	virtual ~QCA_RSAKeyContext() {}

	virtual QCA_RSAKeyContext *clone() const=0;
	virtual bool isNull() const=0;
	virtual bool havePublic() const=0;
	virtual bool havePrivate() const=0;
	virtual bool createFromDER(const char *in, unsigned int len)=0;
	virtual bool createFromPEM(const char *in, unsigned int len)=0;
	virtual bool createFromNative(void *in)=0;
	virtual bool generate(unsigned int bits)=0;
	virtual bool toDER(QByteArray *out, bool publicOnly)=0;
	virtual bool toPEM(QByteArray *out, bool publicOnly)=0;

	virtual bool encrypt(const QByteArray &in, QByteArray *out, bool oaep)=0;
	virtual bool decrypt(const QByteArray &in, QByteArray *out, bool oaep)=0;
};

struct QCA_CertProperty
{
	QString var;
	QString val;
};

class QCA_CertContext
{
public:
	virtual ~QCA_CertContext() {}

	virtual QCA_CertContext *clone() const=0;
	virtual bool isNull() const=0;
	virtual bool createFromDER(const char *in, unsigned int len)=0;
	virtual bool createFromPEM(const char *in, unsigned int len)=0;
	virtual bool toDER(QByteArray *out)=0;
	virtual bool toPEM(QByteArray *out)=0;

	virtual QString serialNumber() const=0;
	virtual QString subjectString() const=0;
	virtual QString issuerString() const=0;
	virtual QValueList<QCA_CertProperty> subject() const=0;
	virtual QValueList<QCA_CertProperty> issuer() const=0;
	virtual QDateTime notBefore() const=0;
	virtual QDateTime notAfter() const=0;
	virtual bool matchesAddress(const QString &realHost) const=0;
};

class QCA_TLSContext
{
public:
	enum Result { Success, Error, Continue };
	virtual ~QCA_TLSContext() {}

	virtual void reset()=0;
	virtual bool startClient(const QPtrList<QCA_CertContext> &store, const QCA_CertContext &cert, const QCA_RSAKeyContext &key)=0;
	virtual bool startServer(const QPtrList<QCA_CertContext> &store, const QCA_CertContext &cert, const QCA_RSAKeyContext &key)=0;

	virtual int handshake(const QByteArray &in, QByteArray *out)=0;
	virtual int shutdown(const QByteArray &in, QByteArray *out)=0;
	virtual bool encode(const QByteArray &plain, QByteArray *to_net, int *encoded)=0;
	virtual bool decode(const QByteArray &from_net, QByteArray *plain, QByteArray *to_net)=0;
	virtual bool eof() const=0;
	virtual QByteArray unprocessed()=0;

	virtual QCA_CertContext *peerCertificate() const=0;
	virtual int validityResult() const=0;
};

struct QCA_SASLHostPort
{
	QHostAddress addr;
	Q_UINT16 port;
};

struct QCA_SASLNeedParams
{
	bool user, authzid, pass, realm;
};

class QCA_SASLContext
{
public:
	enum Result { Success, Error, NeedParams, AuthCheck, Continue };
	virtual ~QCA_SASLContext() {}

	// common
	virtual void reset()=0;
	virtual void setCoreProps(const QString &service, const QString &host, QCA_SASLHostPort *local, QCA_SASLHostPort *remote)=0;
	virtual void setSecurityProps(bool noPlain, bool noActive, bool noDict, bool noAnon, bool reqForward, bool reqCreds, bool reqMutual, int ssfMin, int ssfMax, const QString &_ext_authid, int _ext_ssf)=0;
	virtual int security() const=0;
	virtual int errorCond() const=0;

	// init / first step
	virtual bool clientStart(const QStringList &mechlist)=0;
	virtual int clientFirstStep(bool allowClientSendFirst)=0;
	virtual bool serverStart(const QString &realm, QStringList *mechlist, const QString &name)=0;
	virtual int serverFirstStep(const QString &mech, const QByteArray *in)=0;

	// get / set params
	virtual QCA_SASLNeedParams clientParamsNeeded() const=0;
	virtual void setClientParams(const QString *user, const QString *authzid, const QString *pass, const QString *realm)=0;
	virtual QString username() const=0;
	virtual QString authzid() const=0;

	// continue steps
	virtual int nextStep(const QByteArray &in)=0;
	virtual int tryAgain()=0;

	// results
	virtual QString mech() const=0;
	virtual const QByteArray *clientInit() const=0;
	virtual QByteArray result() const=0;

	// security layer
	virtual bool encode(const QByteArray &in, QByteArray *out)=0;
	virtual bool decode(const QByteArray &in, QByteArray *out)=0;
};

#endif
