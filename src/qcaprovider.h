#ifndef QCAPROVIDER_H
#define QCAPROVIDER_H

#include<qglobal.h>
#include<qstring.h>
#include<qdatetime.h>
#include<qobject.h>
#include<qhostaddress.h>
#include"qca.h"

#ifdef Q_WS_WIN
#define QCA_EXPORT extern "C" __declspec(dllexport)
#else
#define QCA_EXPORT extern "C"
#endif

class QCAProvider
{
public:
	QCAProvider() {}
	virtual ~QCAProvider() {}

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
	virtual void final(char **out, unsigned int *outlen)=0;
};

class QCA_CipherContext
{
public:
	virtual ~QCA_CipherContext() {}

	virtual QCA_CipherContext *clone()=0;
	virtual int keySize()=0;
	virtual int blockSize()=0;
	virtual bool generateKey(char *out)=0;
	virtual bool generateIV(char *out)=0;

	virtual bool setup(int dir, int mode, const char *key, int keysize, const char *iv, bool pad)=0;
	virtual bool update(const char *in, unsigned int len)=0;
	virtual bool final(char **out, unsigned int *outlen)=0;
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
	virtual void toDER(char **out, unsigned int *len, bool publicOnly)=0;
	virtual void toPEM(char **out, unsigned int *len, bool publicOnly)=0;

	virtual bool encrypt(const char *in, unsigned int len, char **out, unsigned int *outlen, bool oaep)=0;
	virtual bool decrypt(const char *in, unsigned int len, char **out, unsigned int *outlen, bool oaep)=0;
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
	virtual void toDER(char **out, unsigned int *len)=0;
	virtual void toPEM(char **out, unsigned int *len)=0;

	virtual QString serialNumber() const=0;
	virtual QString subjectString() const=0;
	virtual QString issuerString() const=0;
	virtual QValueList<QCA_CertProperty> subject() const=0;
	virtual QValueList<QCA_CertProperty> issuer() const=0;
	virtual QDateTime notBefore() const=0;
	virtual QDateTime notAfter() const=0;
};

class QCA_SSLContext : public QObject
{
	Q_OBJECT
public:
	virtual ~QCA_SSLContext() {}

	virtual bool startClient(const QString &host, const QPtrList<QCA_CertContext> &store)=0;
	virtual bool startServer(const QCA_CertContext &cert, const QCA_RSAKeyContext &key)=0;

	virtual void writeIncoming(const QByteArray &a)=0;
	virtual QByteArray readOutgoing()=0;
	virtual void write(const QByteArray &a)=0;
	virtual QByteArray read()=0;
	virtual QCA_CertContext *peerCertificate() const=0;
	virtual int validityResult() const=0;

signals:
	void handshaken(bool);
	void readyRead();
	void readyReadOutgoing();
};

struct QCA_SASLHostPort
{
	QHostAddress addr;
	Q_UINT16 port;
};

struct QCA_SASLNeedParams
{
	bool auth, user, pass, realm;
};

class QCA_SASLContext
{
public:
	enum { Success, Error, NeedParams, Continue };
	virtual ~QCA_SASLContext() {}

	// common
	virtual void reset()=0;
	virtual void setCoreProps(const QString &service, const QString &host, QCA_SASLHostPort *local, QCA_SASLHostPort *remote)=0;
	virtual void setSecurityProps(bool noPlain, bool noActive, bool noDict, bool noAnon, bool reqForward, bool reqCreds, bool reqMutual, int ssfMin, int ssfMax)=0;

	// client
	virtual bool clientStart(const QStringList &mechlist)=0;
	virtual int clientFirstStep(QString *mech, QByteArray **out, QCA_SASLNeedParams *np)=0;
	virtual int clientNextStep(const QByteArray &in, QByteArray *out, QCA_SASLNeedParams *np)=0;

	// server
	virtual bool serverStart(const QString &realm, QStringList *mechlist)=0;
	virtual int serverFirstStep(const QString &mech, const QByteArray *in, QByteArray *out)=0;
	virtual int serverNextStep(const QByteArray &in, QByteArray *out)=0;

	// client params
	virtual void setAuthname(const QString &)=0;
	virtual void setUsername(const QString &)=0;
	virtual void setPassword(const QString &)=0;
	virtual void setRealm(const QString &)=0;
};

#endif
