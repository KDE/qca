/*
 * qca.cpp - Qt Cryptographic Architecture
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

#include"qca.h"

#include<qptrlist.h>
#include<qdir.h>
#include<qfileinfo.h>
#include<qstringlist.h>
#include<qlibrary.h>
#include<qtimer.h>
#include<qhostaddress.h>
#include<qapplication.h>
#include<qguardedptr.h>
#include<stdlib.h>
#include"qcaprovider.h"

#if defined(Q_OS_WIN32)
#define PLUGIN_EXT "dll"
#elif defined(Q_OS_MAC)
#define PLUGIN_EXT "dylib"
#else
#define PLUGIN_EXT "so"
#endif

using namespace QCA;

class ProviderItem
{
public:
	QCAProvider *p;
	QString fname;

	static ProviderItem *load(const QString &fname)
	{
		QLibrary *lib = new QLibrary(fname);
		if(!lib->load()) {
			delete lib;
			return 0;
		}
		void *s = lib->resolve("createProvider");
		if(!s) {
			delete lib;
			return 0;
		}
		QCAProvider *(*createProvider)() = (QCAProvider *(*)())s;
		QCAProvider *p = createProvider();
		if(!p) {
			delete lib;
			return 0;
		}
		ProviderItem *i = new ProviderItem(lib, p);
		i->fname = fname;
		return i;
	}

	static ProviderItem *fromClass(QCAProvider *p)
	{
		ProviderItem *i = new ProviderItem(0, p);
		return i;
	}

	~ProviderItem()
	{
		delete p;
		delete lib;
	}

	void ensureInit()
	{
		if(init_done)
			return;
		init_done = true;
		p->init();
	}

private:
	QLibrary *lib;
	bool init_done;

	ProviderItem(QLibrary *_lib, QCAProvider *_p)
	{
		lib = _lib;
		p = _p;
		init_done = false;
	}
};

static QPtrList<ProviderItem> providerList;
static bool qca_init = false;

static bool plugin_have(const QString &fname)
{
	QPtrListIterator<ProviderItem> it(providerList);
	for(ProviderItem *i; (i = it.current()); ++it) {
		if(i->fname == fname)
			return true;
	}
	return false;
}

static void plugin_scan()
{
	QStringList dirs = QApplication::libraryPaths();
	for(QStringList::ConstIterator it = dirs.begin(); it != dirs.end(); ++it) {
		QDir libpath(*it);
		QDir dir(libpath.filePath("crypto"));
		if(!dir.exists())
			continue;

		QStringList list = dir.entryList();
		for(QStringList::ConstIterator it = list.begin(); it != list.end(); ++it) {
			QFileInfo fi(dir.filePath(*it));
			if(fi.isDir())
				continue;
			if(fi.extension() != PLUGIN_EXT)
				continue;
			QString fname = fi.filePath();

			// don't load the same plugin again!
			if(plugin_have(fname))
				continue;
			//printf("f=[%s]\n", fname.latin1());

			ProviderItem *i = ProviderItem::load(fname);
			if(!i)
				continue;
			if(i->p->qcaVersion() != QCA_PLUGIN_VERSION) {
				delete i;
				continue;
			}

			providerList.append(i);
		}
	}
}

static void plugin_addClass(QCAProvider *p)
{
	ProviderItem *i = ProviderItem::fromClass(p);
	providerList.prepend(i);
}

static void plugin_unloadall()
{
	providerList.clear();
}

static int plugin_caps()
{
	int caps = 0;
	QPtrListIterator<ProviderItem> it(providerList);
	for(ProviderItem *i; (i = it.current()); ++it)
		caps |= i->p->capabilities();
	return caps;
}

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
	providerList.setAutoDelete(true);
}

bool QCA::isSupported(int capabilities)
{
	init();

	int caps = plugin_caps();
	if(caps & capabilities)
		return true;

	// ok, try scanning for new stuff
	plugin_scan();
	caps = plugin_caps();
	if(caps & capabilities)
		return true;

	return false;
}

void QCA::insertProvider(QCAProvider *p)
{
	plugin_addClass(p);
}

void QCA::unloadAllPlugins()
{
	plugin_unloadall();
}

static void *getContext(int cap)
{
	init();

	// this call will also trip a scan for new plugins if needed
	if(!QCA::isSupported(cap))
		return 0;

	QPtrListIterator<ProviderItem> it(providerList);
	for(ProviderItem *i; (i = it.current()); ++it) {
		if(i->p->capabilities() & cap) {
			i->ensureInit();
			return i->p->context(cap);
		}
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
	QByteArray buf;
	d->c->final(&buf);
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

QByteArray Cipher::dyn_generateKey(int size) const
{
	QByteArray buf;
	if(size != -1)
		buf.resize(size);
	else
		buf.resize(d->c->keySize());
	if(!d->c->generateKey(buf.data(), size))
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

	QByteArray out;
	if(!d->c->final(&out)) {
		d->err = true;
		return QByteArray();
	}
	if(ok)
		*ok = true;
	return out;
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
	QByteArray out;
	if(!d->c->toDER(&out, publicOnly))
		return QByteArray();
	return out;
}

bool RSAKey::fromDER(const QByteArray &a)
{
	return d->c->createFromDER(a.data(), a.size());
}

QString RSAKey::toPEM(bool publicOnly) const
{
	QByteArray out;
	if(!d->c->toPEM(&out, publicOnly))
		return QByteArray();

	QCString cs;
	cs.resize(out.size()+1);
	memcpy(cs.data(), out.data(), out.size());
	return QString::fromLatin1(cs);
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
	QByteArray out;
	if(!d->c->encrypt(a, &out, oaep))
		return false;
	*b = out;
	return true;
}

bool RSAKey::decrypt(const QByteArray &a, QByteArray *b, bool oaep) const
{
	QByteArray out;
	if(!d->c->decrypt(a, &out, oaep))
		return false;
	*b = out;
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

QString Cert::commonName() const
{
	CertProperties props = subject();
	return props["CN"];
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
	QByteArray out;
	if(!d->c->toDER(&out))
		return QByteArray();
	return out;
}

bool Cert::fromDER(const QByteArray &a)
{
	return d->c->createFromDER(a.data(), a.size());
}

QString Cert::toPEM() const
{
	QByteArray out;
	if(!d->c->toPEM(&out))
		return QByteArray();

	QCString cs;
	cs.resize(out.size()+1);
	memcpy(cs.data(), out.data(), out.size());
	return QString::fromLatin1(cs);
}

bool Cert::fromPEM(const QString &str)
{
	QCString cs = str.latin1();
	QByteArray a(cs.length());
	memcpy(a.data(), cs.data(), a.size());
	return d->c->createFromPEM(a.data(), a.size());
}


//----------------------------------------------------------------------------
// TLS
//----------------------------------------------------------------------------
class TLS::Private
{
public:
	Private()
	{
		c = (QCA_TLSContext *)getContext(CAP_TLS);
	}

	~Private()
	{
		delete c;
	}

	void reset()
	{
		handshaken = false;
		closing = false;
		in.resize(0);
		out.resize(0);
		from_net.resize(0);
		to_net.resize(0);
		host = "";
		hostMismatch = false;
		cert = Cert();
		bytesEncoded = 0;
		tryMore = false;
	}

	void appendArray(QByteArray *a, const QByteArray &b)
	{
		int oldsize = a->size();
		a->resize(oldsize + b.size());
		memcpy(a->data() + oldsize, b.data(), b.size());
	}

	Cert cert;
	QCA_TLSContext *c;
	QByteArray in, out, to_net, from_net;
	int bytesEncoded;
	bool tryMore;
	bool handshaken;
	QString host;
	bool hostMismatch;
	bool closing;

	Cert ourCert;
	RSAKey ourKey;
	QPtrList<QCA_CertContext> store;
};

TLS::TLS(QObject *parent)
:QObject(parent)
{
	d = new Private;
}

TLS::~TLS()
{
	delete d;
}

void TLS::setCertificate(const Cert &cert, const RSAKey &key)
{
	d->ourCert = cert;
	d->ourKey = key;
}

void TLS::setCertificateStore(const QPtrList<Cert> &store)
{
	// convert the cert list into a context list
	d->store.clear();
	QPtrListIterator<Cert> it(store);
	for(Cert *cert; (cert = it.current()); ++it)
		d->store.append(cert->d->c);
}

void TLS::reset()
{
	d->reset();
}

bool TLS::startClient(const QString &host)
{
	d->reset();
	d->host = host;

	if(!d->c->startClient(d->store, *d->ourCert.d->c, *d->ourKey.d->c))
		return false;
	QTimer::singleShot(0, this, SLOT(update()));
	return true;
}

bool TLS::startServer()
{
	d->reset();

	if(!d->c->startServer(d->store, *d->ourCert.d->c, *d->ourKey.d->c))
		return false;
	QTimer::singleShot(0, this, SLOT(update()));
	return true;
}

void TLS::close()
{
	if(!d->handshaken || d->closing)
		return;

	d->closing = true;
	QTimer::singleShot(0, this, SLOT(update()));
}

bool TLS::isHandshaken() const
{
	return d->handshaken;
}

void TLS::write(const QByteArray &a)
{
	d->appendArray(&d->out, a);
	update();
}

QByteArray TLS::read()
{
	QByteArray a = d->in.copy();
	d->in.resize(0);
	return a;
}

void TLS::writeIncoming(const QByteArray &a)
{
	d->appendArray(&d->from_net, a);
	update();
}

QByteArray TLS::readOutgoing()
{
	QByteArray a = d->to_net.copy();
	d->to_net.resize(0);
	return a;
}

QByteArray TLS::readUnprocessed()
{
	QByteArray a = d->from_net.copy();
	d->from_net.resize(0);
	return a;
}

const Cert & TLS::peerCertificate() const
{
	return d->cert;
}

int TLS::certificateValidityResult() const
{
	if(d->hostMismatch)
		return QCA::TLS::HostMismatch;
	else
		return d->c->validityResult();
}

void TLS::update()
{
	bool force_read = false;
	bool eof = false;
	bool done = false;
	QGuardedPtr<TLS> self = this;

	if(d->closing) {
		QByteArray a;
		int r = d->c->shutdown(d->from_net, &a);
		d->from_net.resize(0);
		if(r == QCA_TLSContext::Error) {
			reset();
			error(ErrHandshake);
			return;
		}
		if(r == QCA_TLSContext::Success) {
			d->from_net = d->c->unprocessed().copy();
			done = true;
		}
		d->appendArray(&d->to_net, a);
	}
	else {
		if(!d->handshaken) {
			QByteArray a;
			int r = d->c->handshake(d->from_net, &a);
			d->from_net.resize(0);
			if(r == QCA_TLSContext::Error) {
				reset();
				error(ErrHandshake);
				return;
			}
			d->appendArray(&d->to_net, a);
			if(r == QCA_TLSContext::Success) {
				QCA_CertContext *cc = d->c->peerCertificate();
				if(cc && !d->host.isEmpty() && d->c->validityResult() == QCA::TLS::Valid) {
					if(!cc->matchesAddress(d->host))
						d->hostMismatch = true;
				}
				d->cert.fromContext(cc);
				d->handshaken = true;
				handshaken();
				if(!self)
					return;

				// there is a teeny tiny possibility that incoming data awaits.  let us get it.
				force_read = true;
			}
		}

		if(d->handshaken) {
			if(!d->out.isEmpty() || d->tryMore) {
				d->tryMore = false;
				QByteArray a;
				int enc;
				bool more = false;
				bool ok = d->c->encode(d->out, &a, &enc);
				eof = d->c->eof();
				if(ok && enc < (int)d->out.size())
					more = true;
				d->out.resize(0);
				if(!eof) {
					if(!ok) {
						reset();
						error(ErrCrypt);
						return;
					}
					d->bytesEncoded += enc;
					if(more)
						d->tryMore = true;
					d->appendArray(&d->to_net, a);
				}
			}
			if(!d->from_net.isEmpty() || force_read) {
				QByteArray a, b;
				bool ok = d->c->decode(d->from_net, &a, &b);
				eof = d->c->eof();
				d->from_net.resize(0);
				if(!ok) {
					reset();
					error(ErrCrypt);
					return;
				}
				d->appendArray(&d->in, a);
				d->appendArray(&d->to_net, b);
			}

			if(!d->in.isEmpty()) {
				readyRead();
				if(!self)
					return;
			}
		}
	}

	if(!d->to_net.isEmpty()) {
		int bytes = d->bytesEncoded;
		d->bytesEncoded = 0;
		readyReadOutgoing(bytes);
		if(!self)
			return;
	}

	if(eof) {
		close();
		if(!self)
			return;
		return;
	}

	if(d->closing && done) {
		reset();
		closed();
	}
}


//----------------------------------------------------------------------------
// SASL
//----------------------------------------------------------------------------
QString saslappname = "qca";
class SASL::Private
{
public:
	Private()
	{
		c = (QCA_SASLContext *)getContext(CAP_SASL);
	}

	~Private()
	{
		delete c;
	}

	void setSecurityProps()
	{
		c->setSecurityProps(noPlain, noActive, noDict, noAnon, reqForward, reqCreds, reqMutual, ssfmin, ssfmax, ext_authid, ext_ssf);
	}

	// security opts
	bool noPlain, noActive, noDict, noAnon, reqForward, reqCreds, reqMutual;
	int ssfmin, ssfmax;
	QString ext_authid;
	int ext_ssf;

	bool tried;
	QCA_SASLContext *c;
	QHostAddress localAddr, remoteAddr;
	int localPort, remotePort;
	QByteArray stepData;
	bool allowCSF;
	bool first, server;

	QByteArray inbuf, outbuf;
};

SASL::SASL(QObject *parent)
:QObject(parent)
{
	d = new Private;
	reset();
}

SASL::~SASL()
{
	delete d;
}

void SASL::setAppName(const QString &name)
{
	saslappname = name;
}

void SASL::reset()
{
	d->localPort = -1;
	d->remotePort = -1;

	d->noPlain = false;
	d->noActive = false;
	d->noDict = false;
	d->noAnon = false;
	d->reqForward = false;
	d->reqCreds = false;
	d->reqMutual = false;
	d->ssfmin = 0;
	d->ssfmax = 0;
	d->ext_authid = "";
	d->ext_ssf = 0;

	d->inbuf.resize(0);
	d->outbuf.resize(0);

	d->c->reset();
}

int SASL::errorCondition() const
{
	return d->c->errorCond();
}

void SASL::setAllowPlain(bool b)
{
	d->noPlain = !b;
}

void SASL::setAllowAnonymous(bool b)
{
	d->noAnon = !b;
}

void SASL::setAllowActiveVulnerable(bool b)
{
	d->noActive = !b;
}

void SASL::setAllowDictionaryVulnerable(bool b)
{
	d->noDict = !b;
}

void SASL::setRequireForwardSecrecy(bool b)
{
	d->reqForward = b;
}

void SASL::setRequirePassCredentials(bool b)
{
	d->reqCreds = b;
}

void SASL::setRequireMutualAuth(bool b)
{
	d->reqMutual = b;
}

void SASL::setMinimumSSF(int x)
{
	d->ssfmin = x;
}

void SASL::setMaximumSSF(int x)
{
	d->ssfmax = x;
}

void SASL::setExternalAuthID(const QString &authid)
{
	d->ext_authid = authid;
}

void SASL::setExternalSSF(int x)
{
	d->ext_ssf = x;
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

bool SASL::startClient(const QString &service, const QString &host, const QStringList &mechlist, bool allowClientSendFirst)
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

	d->allowCSF = allowClientSendFirst;
	d->c->setCoreProps(service, host, d->localPort != -1 ? &la : 0, d->remotePort != -1 ? &ra : 0);
	d->setSecurityProps();

	if(!d->c->clientStart(mechlist))
		return false;
	d->first = true;
	d->server = false;
	d->tried = false;
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
	d->setSecurityProps();

	if(!d->c->serverStart(realm, mechlist, saslappname))
		return false;
	d->first = true;
	d->server = true;
	d->tried = false;
	return true;
}

void SASL::putServerFirstStep(const QString &mech)
{
	int r = d->c->serverFirstStep(mech, 0);
	handleServerFirstStep(r);
}

void SASL::putServerFirstStep(const QString &mech, const QByteArray &clientInit)
{
	int r = d->c->serverFirstStep(mech, &clientInit);
	handleServerFirstStep(r);
}

void SASL::handleServerFirstStep(int r)
{
	if(r == QCA_SASLContext::Success)
		authenticated();
	else if(r == QCA_SASLContext::Continue)
		nextStep(d->c->result());
	else if(r == QCA_SASLContext::AuthCheck)
		tryAgain();
	else
		error(ErrAuth);
}

void SASL::putStep(const QByteArray &stepData)
{
	d->stepData = stepData.copy();
	tryAgain();
}

void SASL::setUsername(const QString &user)
{
	d->c->setClientParams(&user, 0, 0, 0);
}

void SASL::setAuthzid(const QString &authzid)
{
	d->c->setClientParams(0, &authzid, 0, 0);
}

void SASL::setPassword(const QString &pass)
{
	d->c->setClientParams(0, 0, &pass, 0);
}

void SASL::setRealm(const QString &realm)
{
	d->c->setClientParams(0, 0, 0, &realm);
}

void SASL::continueAfterParams()
{
	tryAgain();
}

void SASL::continueAfterAuthCheck()
{
	tryAgain();
}

void SASL::tryAgain()
{
	int r;

	if(d->server) {
		if(!d->tried) {
			r = d->c->nextStep(d->stepData);
			d->tried = true;
		}
		else {
			r = d->c->tryAgain();
		}

		if(r == QCA_SASLContext::Error) {
			error(ErrAuth);
			return;
		}
		else if(r == QCA_SASLContext::Continue) {
			d->tried = false;
			nextStep(d->c->result());
			return;
		}
		else if(r == QCA_SASLContext::AuthCheck) {
			authCheck(d->c->username(), d->c->authzid());
			return;
		}
	}
	else {
		if(d->first) {
			if(!d->tried) {
				r = d->c->clientFirstStep(d->allowCSF);
				d->tried = true;
			}
			else
				r = d->c->tryAgain();

			if(r == QCA_SASLContext::Error) {
				error(ErrAuth);
				return;
			}
			else if(r == QCA_SASLContext::NeedParams) {
				//d->tried = false;
				QCA_SASLNeedParams np = d->c->clientParamsNeeded();
				needParams(np.user, np.authzid, np.pass, np.realm);
				return;
			}

			QString mech = d->c->mech();
			const QByteArray *clientInit = d->c->clientInit();

			d->first = false;
			d->tried = false;
			clientFirstStep(mech, clientInit);
		}
		else {
			if(!d->tried) {
				r = d->c->nextStep(d->stepData);
				d->tried = true;
			}
			else
				r = d->c->tryAgain();

			if(r == QCA_SASLContext::Error) {
				error(ErrAuth);
				return;
			}
			else if(r == QCA_SASLContext::NeedParams) {
				//d->tried = false;
				QCA_SASLNeedParams np = d->c->clientParamsNeeded();
				needParams(np.user, np.authzid, np.pass, np.realm);
				return;
			}
			d->tried = false;
			//else if(r == QCA_SASLContext::Continue) {
				nextStep(d->c->result());
			//	return;
			//}
		}
	}

	if(r == QCA_SASLContext::Success)
		authenticated();
	else if(r == QCA_SASLContext::Error)
		error(ErrAuth);
}

int SASL::ssf() const
{
	return d->c->security();
}

void SASL::write(const QByteArray &a)
{
	QByteArray b;
	if(!d->c->encode(a, &b)) {
		error(ErrCrypt);
		return;
	}
	int oldsize = d->outbuf.size();
	d->outbuf.resize(oldsize + b.size());
	memcpy(d->outbuf.data() + oldsize, b.data(), b.size());
	readyReadOutgoing(a.size());
}

QByteArray SASL::read()
{
	QByteArray a = d->inbuf.copy();
	d->inbuf.resize(0);
	return a;
}

void SASL::writeIncoming(const QByteArray &a)
{
	QByteArray b;
	if(!d->c->decode(a, &b)) {
		error(ErrCrypt);
		return;
	}
	int oldsize = d->inbuf.size();
	d->inbuf.resize(oldsize + b.size());
	memcpy(d->inbuf.data() + oldsize, b.data(), b.size());
	readyRead();
}

QByteArray SASL::readOutgoing()
{
	QByteArray a = d->outbuf.copy();
	d->outbuf.resize(0);
	return a;
}
