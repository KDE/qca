#include"qca.h"

#include<qptrlist.h>
#include<qdir.h>
#include<qfileinfo.h>
#include<qstringlist.h>
#include<qlibrary.h>
#include"qcaprovider.h"
#include<stdio.h>

#ifdef USE_OPENSSL
#include"qcaopenssl.h"
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
	providerList.clear();
#ifdef USE_OPENSSL
	providerList.append(createProviderOpenSSL());
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
	int caps = 0;
	QPtrListIterator<QCAProvider> it(providerList);
	for(QCAProvider *p; (p = it.current()); ++it)
		caps |= p->capabilities();
	if(caps & capabilities)
		return true;
	else
		return false;
}

static void *getFunctions(int cap)
{
	QPtrListIterator<QCAProvider> it(providerList);
	for(QCAProvider *p; (p = it.current()); ++it) {
		if(p->capabilities() & cap)
			return p->functions(cap);
	}
	return 0;
}


//----------------------------------------------------------------------------
// Hash
//----------------------------------------------------------------------------
class Hash::Private
{
public:
	Private(QCA_HashContext *_c)
	{
		c = _c;
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
	d = new Private(c);
}

Hash::Hash(const Hash &from)
{
	d = new Private(from.d->c);
	*this = from;
}

Hash & Hash::operator=(const Hash &)
{
	clear();
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
	Private(QCA_CipherContext *_c)
	{
		c = _c;
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

Cipher::Cipher(QCA_CipherContext *c, int dir, int mode, const QByteArray &key, const QByteArray &iv)
{
	d = new Private(c);
	reset(dir, mode, key, iv);
}

Cipher::Cipher(const Cipher &from)
{
	d = new Private(from.d->c);
	*this = from;
}

Cipher & Cipher::operator=(const Cipher &from)
{
	reset(from.d->dir, from.d->mode, from.d->key, from.d->iv);
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

void Cipher::reset(int dir, int mode, const QByteArray &key, const QByteArray &iv)
{
	d->reset();
	if((int)key.size() != d->c->keySize())
		return;
	if(!iv.isEmpty() && (int)iv.size() != d->c->blockSize())
		return;

	d->dir = dir;
	d->mode = mode;
	d->key = key.copy();
	d->iv = iv.copy();
	if(!d->c->setup(d->dir, d->mode, d->key.data(), d->iv.isEmpty() ? 0 : d->iv.data())) {
		d->err = true;
		return;
	}
}

bool Cipher::update(const QByteArray &a)
{
	if(d->err)
		return false;

	if(!d->c->update(a.data(), a.size())) {
		d->err = true;
		return false;
	}
	return true;
}

QByteArray Cipher::final()
{
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
	return buf;
}


//----------------------------------------------------------------------------
// SHA1
//----------------------------------------------------------------------------
SHA1::SHA1()
:Hash((QCA_HashContext *)getFunctions(CAP_SHA1))
{
}


//----------------------------------------------------------------------------
// SHA256
//----------------------------------------------------------------------------
SHA256::SHA256()
:Hash((QCA_HashContext *)getFunctions(CAP_SHA256))
{
}


//----------------------------------------------------------------------------
// MD5
//----------------------------------------------------------------------------
MD5::MD5()
:Hash((QCA_HashContext *)getFunctions(CAP_MD5))
{
}


//----------------------------------------------------------------------------
// BlowFish
//----------------------------------------------------------------------------
BlowFish::BlowFish(int dir, int mode, const QByteArray &key, const QByteArray &iv)
:Cipher((QCA_CipherContext *)getFunctions(CAP_BlowFish), dir, mode, key, iv)
{
}


//----------------------------------------------------------------------------
// TripleDES
//----------------------------------------------------------------------------
TripleDES::TripleDES(int dir, int mode, const QByteArray &key, const QByteArray &iv)
:Cipher((QCA_CipherContext *)getFunctions(CAP_TripleDES), dir, mode, key, iv)
{
}


//----------------------------------------------------------------------------
// AES128
//----------------------------------------------------------------------------
AES128::AES128(int dir, int mode, const QByteArray &key, const QByteArray &iv)
:Cipher((QCA_CipherContext *)getFunctions(CAP_AES128), dir, mode, key, iv)
{
}


//----------------------------------------------------------------------------
// AES256
//----------------------------------------------------------------------------
AES256::AES256(int dir, int mode, const QByteArray &key, const QByteArray &iv)
:Cipher((QCA_CipherContext *)getFunctions(CAP_AES256), dir, mode, key, iv)
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
		c = (QCA_RSAKeyContext *)getFunctions(CAP_RSA);
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
}

RSAKey::RSAKey(const RSAKey &from)
{
	d = new Private;
	*this = from;
}

RSAKey & RSAKey::operator=(const RSAKey &from)
{
	if(d->c)
		delete d->c;
	*d = *from.d;
	d->c = d->c->clone();

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
