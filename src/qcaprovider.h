/*
 * qcaprovider.h - QCA Plugin API
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

#ifndef QCAPROVIDER_H
#define QCAPROVIDER_H

#include<qglobal.h>
#include<qstring.h>
#include<qdatetime.h>
#include<qobject.h>
#include<qhostaddress.h>
#include"qca.h"

#define QCA_PLUGIN_VERSION 1

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
