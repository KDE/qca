#include"qca.h"

#include<qptrlist.h>
#include<qdir.h>
#include<qfileinfo.h>
#include<qstringlist.h>
#include<qlibrary.h>
#include"qcaprovider.h"
#include<stdio.h>

#ifdef USE_OPENSSL
#include"qcaopenssl_p.h"
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
	providerList.append(new _QCAOpenSSL);
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
	Private(QCA_HashFunctions *_f)
	{
		f = _f;
		ctx = f->create();
	}

	~Private()
	{
		f->destroy(ctx);
	}

	void reset()
	{
		f->destroy(ctx);
		ctx = f->create();
	}

	QCA_HashFunctions *f;
	int ctx;
};

Hash::Hash(QCA_HashFunctions *f)
{
	d = new Private(f);
}

Hash::Hash(const Hash &from)
{
	d = new Private(from.d->f);
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
	d->f->update(d->ctx, a.data(), a.size());
}

QByteArray Hash::final()
{
	QByteArray buf(d->f->finalSize(d->ctx));
	d->f->final(d->ctx, buf.data());
	return buf;
}


//----------------------------------------------------------------------------
// Cipher
//----------------------------------------------------------------------------
class Cipher::Private
{
public:
	Private(QCA_CipherFunctions *_f)
	{
		f = _f;
		ctx = f->create();
	}

	~Private()
	{
		f->destroy(ctx);
	}

	void reset()
	{
		f->destroy(ctx);
		ctx = f->create();
		dir = Encrypt;
		key.resize(0);
		iv.resize(0);
		err = false;
	}

	QCA_CipherFunctions *f;
	int ctx;
	int dir;
	int mode;
	QByteArray key, iv;
	bool err;
};

Cipher::Cipher(QCA_CipherFunctions *f, int dir, int mode, const QByteArray &key, const QByteArray &iv)
{
	d = new Private(f);
	reset(dir, mode, key, iv);
}

Cipher::Cipher(const Cipher &from)
{
	d = new Private(from.d->f);
	*this = from;
}

Cipher & Cipher::operator=(const Cipher &from)
{
	reset(from.d->dir, from.d->key, from.d->iv);
	return *this;
}

Cipher::~Cipher()
{
	delete d;
}

QByteArray Cipher::dyn_generateKey() const
{
	QByteArray buf(d->f->keySize());
	if(!d->f->generateKey(buf.data()))
		return QByteArray();
	return buf;
}

QByteArray Cipher::dyn_generateIV() const
{
	QByteArray buf(d->f->blockSize());
	if(!d->f->generateIV(buf.data()))
		return QByteArray();
	return buf;
}

void Cipher::reset(int dir, int mode, const QByteArray &key, const QByteArray &iv)
{
	d->reset();
	d->dir = dir;
	d->mode = mode;
	d->key = key.copy();
	d->iv = iv.copy();
	if(!d->f->setup(d->ctx, d->dir, d->mode, d->key.data(), d->iv.isEmpty() ? 0 : d->iv.data())) {
		d->err = true;
		return;
	}
}

bool Cipher::update(const QByteArray &a)
{
	if(d->err)
		return false;

	if(!d->f->update(d->ctx, a.data(), a.size())) {
		d->err = true;
		return false;
	}
	return true;
}

QByteArray Cipher::final()
{
	if(d->err)
		return QByteArray();

	QByteArray buf(d->f->finalSize(d->ctx));
	if(!d->f->final(d->ctx, buf.data())) {
		d->err = true;
		return QByteArray();
	}

	return buf;
}


//----------------------------------------------------------------------------
// SHA1
//----------------------------------------------------------------------------
SHA1::SHA1()
:Hash((QCA_HashFunctions *)getFunctions(CAP_SHA1))
{
}


//----------------------------------------------------------------------------
// SHA256
//----------------------------------------------------------------------------
SHA256::SHA256()
:Hash((QCA_HashFunctions *)getFunctions(CAP_SHA256))
{
}


//----------------------------------------------------------------------------
// MD5
//----------------------------------------------------------------------------
MD5::MD5()
:Hash((QCA_HashFunctions *)getFunctions(CAP_MD5))
{
}


//----------------------------------------------------------------------------
// BlowFish
//----------------------------------------------------------------------------
BlowFish::BlowFish(int dir, int mode, const QByteArray &key, const QByteArray &iv)
:Cipher((QCA_CipherFunctions *)getFunctions(CAP_BlowFish), dir, mode, key, iv)
{
}


//----------------------------------------------------------------------------
// TripleDES
//----------------------------------------------------------------------------
TripleDES::TripleDES(int dir, int mode, const QByteArray &key, const QByteArray &iv)
:Cipher((QCA_CipherFunctions *)getFunctions(CAP_TripleDES), dir, mode, key, iv)
{
}


//----------------------------------------------------------------------------
// AES128
//----------------------------------------------------------------------------
AES128::AES128(int dir, int mode, const QByteArray &key, const QByteArray &iv)
:Cipher((QCA_CipherFunctions *)getFunctions(CAP_AES128), dir, mode, key, iv)
{
}


//----------------------------------------------------------------------------
// AES256
//----------------------------------------------------------------------------
AES256::AES256(int dir, int mode, const QByteArray &key, const QByteArray &iv)
:Cipher((QCA_CipherFunctions *)getFunctions(CAP_AES256), dir, mode, key, iv)
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
		f = (QCA_RSAFunctions *)getFunctions(CAP_RSA);
		ctx = -1;
	}

	~Private()
	{
		reset();
	}

	void reset()
	{
		if(ctx != -1) {
			f->keyDestroy(ctx);
			ctx = -1;
		}
	}

	QCA_RSAFunctions *f;
	int ctx;
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
	d->reset();
	*d = *from.d;
	if(d->ctx != -1)
		d->ctx = d->f->keyClone(d->ctx);
	return *this;
}

RSAKey::~RSAKey()
{
	delete d;
}

bool RSAKey::isNull() const
{
	return (d->ctx == -1 ? true: false);
}

QByteArray RSAKey::toDER() const
{
	char *out;
	unsigned int len;
	d->f->keyToDER(d->ctx, &out, &len);
	QByteArray buf(len);
	memcpy(buf.data(), out, len);
	free(out);
	return buf;
}

bool RSAKey::fromDER(const QByteArray &a, bool sec)
{
	int ctx = d->f->keyCreateFromDER(a.data(), a.size(), sec);
	if(ctx == -1)
		return false;
	d->ctx = ctx;
	return true;
}

bool RSAKey::fromNative(void *p)
{
	int ctx = d->f->keyCreateFromNative(p);
	if(ctx == -1)
		return false;
	d->ctx = ctx;
	return true;
}

bool RSAKey::generate(unsigned int bits)
{
	int ctx = d->f->keyCreateGenerate(bits);
	if(ctx == -1)
		return false;
	d->ctx = ctx;
	return true;
}

int RSAKey::internalContext() const
{
	return d->ctx;
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

bool RSA::encrypt(const QByteArray &a, QByteArray *b) const
{
	if(v_key.isNull())
		return false;

	QCA_RSAFunctions *f = (QCA_RSAFunctions *)getFunctions(CAP_RSA);
	char *out;
	unsigned int len;
	if(!f->encrypt(v_key.internalContext(), a.data(), a.size(), &out, &len))
		return false;

	b->resize(len);
	memcpy(b->data(), out, len);
	free(out);
	return true;
}

bool RSA::decrypt(const QByteArray &a, QByteArray *b) const
{
	if(v_key.isNull())
		return false;

	QCA_RSAFunctions *f = (QCA_RSAFunctions *)getFunctions(CAP_RSA);
	char *out;
	unsigned int len;
	if(!f->decrypt(v_key.internalContext(), a.data(), a.size(), &out, &len))
		return false;

	b->resize(len);
	memcpy(b->data(), out, len);
	free(out);
	return true;
}

RSAKey RSA::generateKey(unsigned int bits)
{
	RSAKey k;
	k.generate(bits);
	return k;
}
