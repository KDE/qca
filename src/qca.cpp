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
	}

	QCA_CipherFunctions *f;
	int ctx;
	int dir;
	QByteArray key, iv;
};

Cipher::Cipher(QCA_CipherFunctions *f, int dir, const QByteArray &key, const QByteArray &iv)
{
	d = new Private(f);
	reset(dir, key, iv);
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
	return QByteArray(24);
}

QByteArray Cipher::dyn_generateIV() const
{
	return QByteArray(8);
}

void Cipher::reset(int dir, const QByteArray &key, const QByteArray &iv)
{
	d->reset();
	d->dir = dir;
	d->key = key.copy();
	d->iv = iv.copy();
}

void Cipher::update(const QByteArray &a)
{
	d->f->setup(d->ctx, d->dir, d->key.data(), d->iv.isEmpty() ? 0 : d->iv.data());
	d->f->update(d->ctx, a.data(), a.size());
}

QByteArray Cipher::final()
{
	QByteArray buf(d->f->finalSize(d->ctx));
	d->f->final(d->ctx, buf.data());
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
// TripleDES
//----------------------------------------------------------------------------
TripleDES::TripleDES(int dir, const QByteArray &key, const QByteArray &iv)
:Cipher((QCA_CipherFunctions *)getFunctions(CAP_TripleDES), dir, key, iv)
{
}


//----------------------------------------------------------------------------
// AES128
//----------------------------------------------------------------------------
AES128::AES128(int dir, const QByteArray &key, const QByteArray &iv)
:Cipher((QCA_CipherFunctions *)getFunctions(CAP_AES128), dir, key, iv)
{
}


//----------------------------------------------------------------------------
// AES256
//----------------------------------------------------------------------------
AES256::AES256(int dir, const QByteArray &key, const QByteArray &iv)
:Cipher((QCA_CipherFunctions *)getFunctions(CAP_AES256), dir, key, iv)
{
}
