#include"qca.h"

#include<qptrlist.h>
#include<qdir.h>
#include<qfileinfo.h>
#include<qstringlist.h>
#include<qlibrary.h>
#include<qtimer.h>
#include<qhostaddress.h>
#include"qcaprovider.h"
#include<stdio.h>
#include<stdlib.h>

#ifdef USE_OPENSSL
#include"qcaopenssl.h"
#endif

#ifdef USE_CYRUSSASL
#include"qcacyrussasl.h"
#endif

#if defined(Q_OS_WIN32)
#define PLUGIN_EXT "dll"
#elif defined(Q_OS_MAC)
#define PLUGIN_EXT "dylib"
#else
#define PLUGIN_EXT "so"
#endif

using namespace QCA;

static QPtrList<QCAProvider> providerList;
static bool qca_init = false;

QString QCA::arrayToHex(const QByteArray &a)
{
	QString out;
	for(int n = 0; n < (int)a.size(); ++n) {
		QString str;
		str.sprintf("%02x", (uchar)a[n]);
		out.append(str);
	}
	return out;
}

QByteArray QCA::hexToArray(const QString &str)
{
	QByteArray out(str.length() / 2);
	int at = 0;
	for(int n = 0; n + 1 < (int)str.length(); n += 2) {
		uchar a = str[n];
		uchar b = str[n+1];
		uchar c = ((a & 0x0f) << 4) + (b & 0x0f);
		out[at++] = c;
	}
	return out;
}

void QCA::init()
{
	if(qca_init)
		return;
	qca_init = true;

	providerList.clear();
#ifdef USE_OPENSSL
	providerList.append(createProviderOpenSSL());
#endif
#ifdef USE_CYRUSSASL
	providerList.append(createProviderCyrusSASL());
#endif

	// load plugins
	QDir dir("plugins");
	QStringList list = dir.entryList();
	for(QStringList::ConstIterator it = list.begin(); it != list.end(); ++it) {
		QFileInfo fi(dir.filePath(*it));
		//printf("f=[%s]\n", fi.filePath().latin1());
		if(fi.extension() != PLUGIN_EXT)
			continue;

		QLibrary *lib = new QLibrary(fi.filePath());
		if(!lib->load()) {
			delete lib;
			//printf("can't load\n");
			continue;
		}
		void *s = lib->resolve("createProvider");
		if(!s) {
			delete lib;
			continue;
		}
		QCAProvider *(*createProvider)() = (QCAProvider *(*)())s;
		QCAProvider *p = createProvider();
		if(!p) {
			delete lib;
			continue;
		}
		providerList.append(p);
	}
}

bool QCA::isSupported(int capabilities)
{
	init();

	int caps = 0;
	QPtrListIterator<QCAProvider> it(providerList);
	for(QCAProvider *p; (p = it.current()); ++it)
		caps |= p->capabilities();
	if(caps & capabilities)
		return true;
	else
		return false;
}

static void *getContext(int cap)
{
	init();

	QPtrListIterator<QCAProvider> it(providerList);
	for(QCAProvider *p; (p = it.current()); ++it) {
		if(p->capabilities() & cap)
			return p->context(cap);
	}
	return 0;
}


//----------------------------------------------------------------------------
// Hash
//----------------------------------------------------------------------------
class Hash::Private
{
public:
	Private()
	{
		c = 0;
	}

	~Private()
	{
		delete c;
	}

	void reset()
	{
		c->reset();
	}

	QCA_HashContext *c;
};

Hash::Hash(QCA_HashContext *c)
{
	d = new Private;
	d->c = c;
}

Hash::Hash(const Hash &from)
{
	d = new Private;
	*this = from;
}

Hash & Hash::operator=(const Hash &from)
{
	delete d->c;
	d->c = from.d->c->clone();
	return *this;
}

Hash::~Hash()
{
	delete d;
}

void Hash::clear()
{
	d->reset();
}

void Hash::update(const QByteArray &a)
{
	d->c->update(a.data(), a.size());
}

QByteArray Hash::final()
{
	char *out;
	unsigned int len;
	d->c->final(&out, &len);
	QByteArray buf(len);
	memcpy(buf.data(), out, len);
	free(out);
	return buf;
}


//----------------------------------------------------------------------------
// Cipher
//----------------------------------------------------------------------------
class Cipher::Private
{
public:
	Private()
	{
		c = 0;
	}

	~Private()
	{
		delete c;
	}

	void reset()
	{
		dir = Encrypt;
		key.resize(0);
		iv.resize(0);
		err = false;
	}

	QCA_CipherContext *c;
	int dir;
	int mode;
	QByteArray key, iv;
	bool err;
};

Cipher::Cipher(QCA_CipherContext *c, int dir, int mode, const QByteArray &key, const QByteArray &iv, bool pad)
{
	d = new Private;
	d->c = c;
	reset(dir, mode, key, iv, pad);
}

Cipher::Cipher(const Cipher &from)
{
	d = new Private;
	*this = from;
}

Cipher & Cipher::operator=(const Cipher &from)
{
	delete d->c;
	d->c = from.d->c->clone();
	d->dir = from.d->dir;
	d->mode = from.d->mode;
	d->key = from.d->key.copy();
	d->iv = from.d->iv.copy();
	d->err = from.d->err;
	return *this;
}

Cipher::~Cipher()
{
	delete d;
}

QByteArray Cipher::dyn_generateKey() const
{
	QByteArray buf(d->c->keySize());
	if(!d->c->generateKey(buf.data()))
		return QByteArray();
	return buf;
}

QByteArray Cipher::dyn_generateIV() const
{
	QByteArray buf(d->c->blockSize());
	if(!d->c->generateIV(buf.data()))
		return QByteArray();
	return buf;
}

void Cipher::reset(int dir, int mode, const QByteArray &key, const QByteArray &iv, bool pad)
{
	d->reset();

	d->dir = dir;
	d->mode = mode;
	d->key = key.copy();
	d->iv = iv.copy();
	if(!d->c->setup(d->dir, d->mode, d->key.isEmpty() ? 0: d->key.data(), d->key.size(), d->iv.isEmpty() ? 0 : d->iv.data(), pad)) {
		d->err = true;
		return;
	}
}

bool Cipher::update(const QByteArray &a)
{
	if(d->err)
		return false;

	if(!a.isEmpty()) {
		if(!d->c->update(a.data(), a.size())) {
			d->err = true;
			return false;
		}
	}
	return true;
}

QByteArray Cipher::final(bool *ok)
{
	if(ok)
		*ok = false;
	if(d->err)
		return QByteArray();

	char *out;
	unsigned int len;
	if(!d->c->final(&out, &len)) {
		d->err = true;
		return QByteArray();
	}
	QByteArray buf(len);
	memcpy(buf.data(), out, len);
	free(out);
	if(ok)
		*ok = true;
	return buf;
}


//----------------------------------------------------------------------------
// SHA1
//----------------------------------------------------------------------------
SHA1::SHA1()
:Hash((QCA_HashContext *)getContext(CAP_SHA1))
{
}


//----------------------------------------------------------------------------
// SHA256
//----------------------------------------------------------------------------
SHA256::SHA256()
:Hash((QCA_HashContext *)getContext(CAP_SHA256))
{
}


//----------------------------------------------------------------------------
// MD5
//----------------------------------------------------------------------------
MD5::MD5()
:Hash((QCA_HashContext *)getContext(CAP_MD5))
{
}


//----------------------------------------------------------------------------
// BlowFish
//----------------------------------------------------------------------------
BlowFish::BlowFish(int dir, int mode, const QByteArray &key, const QByteArray &iv, bool pad)
:Cipher((QCA_CipherContext *)getContext(CAP_BlowFish), dir, mode, key, iv, pad)
{
}


//----------------------------------------------------------------------------
// TripleDES
//----------------------------------------------------------------------------
TripleDES::TripleDES(int dir, int mode, const QByteArray &key, const QByteArray &iv, bool pad)
:Cipher((QCA_CipherContext *)getContext(CAP_TripleDES), dir, mode, key, iv, pad)
{
}


//----------------------------------------------------------------------------
// AES128
//----------------------------------------------------------------------------
AES128::AES128(int dir, int mode, const QByteArray &key, const QByteArray &iv, bool pad)
:Cipher((QCA_CipherContext *)getContext(CAP_AES128), dir, mode, key, iv, pad)
{
}


//----------------------------------------------------------------------------
// AES256
//----------------------------------------------------------------------------
AES256::AES256(int dir, int mode, const QByteArray &key, const QByteArray &iv, bool pad)
:Cipher((QCA_CipherContext *)getContext(CAP_AES256), dir, mode, key, iv, pad)
{
}


//----------------------------------------------------------------------------
// RSAKey
//----------------------------------------------------------------------------
class RSAKey::Private
{
public:
	Private()
	{
		c = 0;
	}

	~Private()
	{
		delete c;
	}

	QCA_RSAKeyContext *c;
};

RSAKey::RSAKey()
{
	d = new Private;
	d->c = (QCA_RSAKeyContext *)getContext(CAP_RSA);
}

RSAKey::RSAKey(const RSAKey &from)
{
	d = new Private;
	*this = from;
}

RSAKey & RSAKey::operator=(const RSAKey &from)
{
	delete d->c;
	d->c = from.d->c->clone();
	return *this;
}

RSAKey::~RSAKey()
{
	delete d;
}

bool RSAKey::isNull() const
{
	return d->c->isNull();
}

bool RSAKey::havePublic() const
{
	return d->c->havePublic();
}

bool RSAKey::havePrivate() const
{
	return d->c->havePrivate();
}

QByteArray RSAKey::toDER(bool publicOnly) const
{
	char *out;
	unsigned int len;
	d->c->toDER(&out, &len, publicOnly);
	if(!out)
		return QByteArray();
	else {
		QByteArray buf(len);
		memcpy(buf.data(), out, len);
		free(out);
		return buf;
	}
}

bool RSAKey::fromDER(const QByteArray &a)
{
	return d->c->createFromDER(a.data(), a.size());
}

QString RSAKey::toPEM(bool publicOnly) const
{
	char *out;
	unsigned int len;
	d->c->toPEM(&out, &len, publicOnly);
	if(!out)
		return QByteArray();
	else {
		QCString cs;
		cs.resize(len+1);
		memcpy(cs.data(), out, len);
		free(out);
		return QString::fromLatin1(cs);
	}
}

bool RSAKey::fromPEM(const QString &str)
{
	QCString cs = str.latin1();
	QByteArray a(cs.length());
	memcpy(a.data(), cs.data(), a.size());
	return d->c->createFromPEM(a.data(), a.size());
}

bool RSAKey::fromNative(void *p)
{
	return d->c->createFromNative(p);
}

bool RSAKey::encrypt(const QByteArray &a, QByteArray *b, bool oaep) const
{
	char *out;
	unsigned int len;
	if(!d->c->encrypt(a.data(), a.size(), &out, &len, oaep))
		return false;
	b->resize(len);
	memcpy(b->data(), out, len);
	free(out);
	return true;
}

bool RSAKey::decrypt(const QByteArray &a, QByteArray *b, bool oaep) const
{
	char *out;
	unsigned int len;
	if(!d->c->decrypt(a.data(), a.size(), &out, &len, oaep))
		return false;
	b->resize(len);
	memcpy(b->data(), out, len);
	free(out);
	return true;
}

bool RSAKey::generate(unsigned int bits)
{
	return d->c->generate(bits);
}


//----------------------------------------------------------------------------
// RSA
//----------------------------------------------------------------------------
RSA::RSA()
{
}

RSA::~RSA()
{
}

RSAKey RSA::key() const
{
	return v_key;
}

void RSA::setKey(const RSAKey &k)
{
	v_key = k;
}

bool RSA::encrypt(const QByteArray &a, QByteArray *b, bool oaep) const
{
	if(v_key.isNull())
		return false;
	return v_key.encrypt(a, b, oaep);
}

bool RSA::decrypt(const QByteArray &a, QByteArray *b, bool oaep) const
{
	if(v_key.isNull())
		return false;
	return v_key.decrypt(a, b, oaep);
}

RSAKey RSA::generateKey(unsigned int bits)
{
	RSAKey k;
	k.generate(bits);
	return k;
}


//----------------------------------------------------------------------------
// Cert
//----------------------------------------------------------------------------
class Cert::Private
{
public:
	Private()
	{
		c = 0;
	}

	~Private()
	{
		delete c;
	}

	QCA_CertContext *c;
};

Cert::Cert()
{
	d = new Private;
	d->c = (QCA_CertContext *)getContext(CAP_X509);
}

Cert::Cert(const Cert &from)
{
	d = new Private;
	*this = from;
}

Cert & Cert::operator=(const Cert &from)
{
	delete d->c;
	d->c = from.d->c->clone();
	return *this;
}

Cert::~Cert()
{
	delete d;
}

void Cert::fromContext(QCA_CertContext *ctx)
{
	delete d->c;
	d->c = ctx;
}

bool Cert::isNull() const
{
	return d->c->isNull();
}

QString Cert::serialNumber() const
{
	return d->c->serialNumber();
}

QString Cert::subjectString() const
{
	return d->c->subjectString();
}

QString Cert::issuerString() const
{
	return d->c->issuerString();
}

CertProperties Cert::subject() const
{
	QValueList<QCA_CertProperty> list = d->c->subject();
	CertProperties props;
	for(QValueList<QCA_CertProperty>::ConstIterator it = list.begin(); it != list.end(); ++it)
		props[(*it).var] = (*it).val;
	return props;
}

CertProperties Cert::issuer() const
{
	QValueList<QCA_CertProperty> list = d->c->issuer();
	CertProperties props;
	for(QValueList<QCA_CertProperty>::ConstIterator it = list.begin(); it != list.end(); ++it)
		props[(*it).var] = (*it).val;
	return props;
}

QDateTime Cert::notBefore() const
{
	return d->c->notBefore();
}

QDateTime Cert::notAfter() const
{
	return d->c->notAfter();
}

QByteArray Cert::toDER() const
{
	char *out;
	unsigned int len;
	d->c->toDER(&out, &len);
	if(!out)
		return QByteArray();
	else {
		QByteArray buf(len);
		memcpy(buf.data(), out, len);
		free(out);
		return buf;
	}
}

bool Cert::fromDER(const QByteArray &a)
{
	return d->c->createFromDER(a.data(), a.size());
}

QString Cert::toPEM() const
{
	char *out;
	unsigned int len;
	d->c->toPEM(&out, &len);
	if(!out)
		return QByteArray();
	else {
		QCString cs;
		cs.resize(len+1);
		memcpy(cs.data(), out, len);
		free(out);
		return QString::fromLatin1(cs);
	}
}

bool Cert::fromPEM(const QString &str)
{
	QCString cs = str.latin1();
	QByteArray a(cs.length());
	memcpy(a.data(), cs.data(), a.size());
	return d->c->createFromPEM(a.data(), a.size());
}


//----------------------------------------------------------------------------
// SSL
//----------------------------------------------------------------------------
class SSL::Private
{
public:
	Private()
	{
		c = (QCA_SSLContext *)getContext(CAP_SSL);
	}

	~Private()
	{
		delete c;
	}

	Cert cert;
	QCA_SSLContext *c;
};

SSL::SSL(QObject *parent)
:QObject(parent)
{
	d = new Private;
	connect(d->c, SIGNAL(handshaken(bool)), SLOT(ctx_handshaken(bool)));
	connect(d->c, SIGNAL(readyRead()), SLOT(ctx_readyRead()));
	connect(d->c, SIGNAL(readyReadOutgoing()), SLOT(ctx_readyReadOutgoing()));
}

SSL::~SSL()
{
	delete d;
}

bool SSL::startClient(const QString &host, const QPtrList<Cert> &store)
{
	d->cert = Cert();

	// convert the cert list into a context list
	QPtrList<QCA_CertContext> list;
	QPtrListIterator<Cert> it(store);
	for(Cert *cert; (cert = it.current()); ++it)
		list.append(cert->d->c);

	// begin!
	if(!d->c->startClient(host, list))
		return false;
	return true;
}

bool SSL::startServer(const Cert &cert, const RSAKey &key)
{
	if(!d->c->startServer(*cert.d->c, *key.d->c))
		return false;
	return true;
}

void SSL::write(const QByteArray &a)
{
	d->c->write(a);
}

QByteArray SSL::read()
{
	return d->c->read();
}

void SSL::writeIncoming(const QByteArray &a)
{
	d->c->writeIncoming(a);
}

QByteArray SSL::readOutgoing()
{
	return d->c->readOutgoing();
}

const Cert & SSL::peerCertificate() const
{
	return d->cert;
}

int SSL::certificateValidityResult() const
{
	return d->c->validityResult();
}

void SSL::ctx_handshaken(bool b)
{
	if(b) {
		// read the cert
		QCA_CertContext *cc = d->c->peerCertificate();
		d->cert.fromContext(cc);
	}
	handshaken(b);
}

void SSL::ctx_readyRead()
{
	readyRead();
}

void SSL::ctx_readyReadOutgoing()
{
	readyReadOutgoing();
}


//----------------------------------------------------------------------------
// SASL
//----------------------------------------------------------------------------
class SASL::Private
{
public:
	Private()
	{
		c = (QCA_SASLContext *)getContext(CAP_SASL);
		localPort = -1;
		remotePort = -1;
		allowPlain = true;
	}

	~Private()
	{
		delete c;
	}

	QCA_SASLContext *c;
	bool allowPlain;
	QHostAddress localAddr, remoteAddr;
	int localPort, remotePort;
	QByteArray stepData;
	bool first, server;
};

SASL::SASL(QObject *parent)
:QObject(parent)
{
	d = new Private;
}

SASL::~SASL()
{
	delete d;
}

// options
bool SASL::allowPlainText() const
{
	return d->allowPlain;
}

void SASL::setAllowPlainText(bool b)
{
	d->allowPlain = b;
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

bool SASL::startClient(const QString &service, const QString &host, const QStringList &mechlist)
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
	d->c->setSecurityProps(d->allowPlain);
	if(!d->c->clientStart(mechlist))
		return false;
	d->first = true;
	d->server = false;
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
	d->c->setSecurityProps(d->allowPlain);
	if(!d->c->serverStart(realm, mechlist))
		return false;
	d->first = true;
	d->server = true;
	return true;
}

void SASL::putServerFirstStep(const QString &mech)
{
	QByteArray buf;
	int r = d->c->serverFirstStep(mech, 0, &buf);
	handleServerFirstStep(r, buf);
}

void SASL::putServerFirstStep(const QString &mech, const QByteArray &clientInit)
{
	QByteArray buf;
	int r = d->c->serverFirstStep(mech, &clientInit, &buf);
	handleServerFirstStep(r, buf);
}

void SASL::handleServerFirstStep(int r, const QByteArray &buf)
{
	if(r == QCA_SASLContext::Success)
		authenticated(true);
	else if(r == QCA_SASLContext::Continue)
		nextStep(buf);
	else
		authenticated(false);
}

void SASL::putStep(const QByteArray &stepData)
{
	d->stepData = stepData.copy();
	tryAgain();
}

void SASL::setAuthname(const QString &auth)
{
	d->c->setAuthname(auth);
}

void SASL::setUsername(const QString &user)
{
	d->c->setUsername(user);
}

void SASL::setPassword(const QString &pass)
{
	d->c->setPassword(pass);
}

void SASL::setRealm(const QString &realm)
{
	d->c->setRealm(realm);
}

void SASL::continueAfterParams()
{
	tryAgain();
}

void SASL::tryAgain()
{
	int r;

	if(d->server) {
		QByteArray out;
		r = d->c->serverNextStep(d->stepData, &out);
		if(r == QCA_SASLContext::Error) {
			authenticated(false);
			return;
		}
		else if(r == QCA_SASLContext::Continue) {
			nextStep(out);
			return;
		}
	}
	else {
		if(d->first) {
			QString mech;
			QByteArray *clientInit;
			QCA_SASLNeedParams np;
			r = d->c->clientFirstStep(&mech, &clientInit, &np);
			if(r == QCA_SASLContext::Error) {
				authenticated(false);
				return;
			}
			else if(r == QCA_SASLContext::NeedParams) {
				needParams(np.auth, np.user, np.pass, np.realm);
				return;
			}

			d->first = false;
			clientFirstStep(mech, clientInit);
			delete clientInit;
		}
		else {
			QByteArray out;
			QCA_SASLNeedParams np;
			r = d->c->clientNextStep(d->stepData, &out, &np);
			if(r == QCA_SASLContext::Error) {
				authenticated(false);
				return;
			}
			else if(r == QCA_SASLContext::NeedParams) {
				needParams(np.auth, np.user, np.pass, np.realm);
				return;
			}
			//else if(r == QCA_SASLContext::Continue) {
				nextStep(out);
			//	return;
			//}
		}
	}

	if(r == QCA_SASLContext::Success)
		authenticated(true);
	else if(r == QCA_SASLContext::Error)
		authenticated(false);
}

/*void SASL::write(const QByteArray &a)
{
}

QByteArray SASL::read()
{
}

void SASL::writeIncoming(const QByteArray &a)
{
}

QByteArray SASL::readOutgoing()
{
}*/
