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
Hash::Hash()
{
}

Hash::~Hash()
{
}


//----------------------------------------------------------------------------
// Cipher
//----------------------------------------------------------------------------
Cipher::Cipher()
{
}

Cipher::~Cipher()
{
}

QByteArray Cipher::key() const
{
	return v_key.copy();
}

QByteArray Cipher::iv() const
{
	return v_iv.copy();
}

void Cipher::setKey(const QByteArray &a)
{
	v_key = a.copy();
}

void Cipher::setIV(const QByteArray &a)
{
	v_iv = a.copy();
}


//----------------------------------------------------------------------------
// SHA1
//----------------------------------------------------------------------------
SHA1::SHA1()
{
	f = (QCA_SHA1Functions *)getFunctions(CAP_SHA1);
	ctx = f->create();
}

SHA1::~SHA1()
{
	f->destroy(ctx);
}

void SHA1::clear()
{
	f->destroy(ctx);
	ctx = f->create();
}

void SHA1::update(const QByteArray &a)
{
	f->update(ctx, a.data(), a.size());
}

QByteArray SHA1::final()
{
	QByteArray buf(20);
	f->final(ctx, buf.data());
	return buf;
}

/*
//----------------------------------------------------------------------------
// SHA256
//----------------------------------------------------------------------------
SHA256::SHA256()
{
}

SHA256::~SHA256()
{
}

void SHA256::clear()
{
}

void SHA256::update(const QByteArray &a)
{
}

QByteArray SHA256::final()
{
	return QByteArray();
}


//----------------------------------------------------------------------------
// MD5
//----------------------------------------------------------------------------
MD5::MD5()
{
}

MD5::~MD5()
{
}

void MD5::clear()
{
}

void MD5::update(const QByteArray &a)
{
}

QByteArray MD5::final()
{
	return QByteArray();
}


//----------------------------------------------------------------------------
// TripleDES
//----------------------------------------------------------------------------
TripleDES::TripleDES()
{
}

TripleDES::~TripleDES()
{
}

bool TripleDES::encrypt(const QByteArray &in, QByteArray *out, bool pad)
{
	return false;
}

bool TripleDES::decrypt(const QByteArray &in, QByteArray *out, bool pad)
{
	return false;
}


//----------------------------------------------------------------------------
// AES128
//----------------------------------------------------------------------------
AES128::AES128()
{
}

AES128::~AES128()
{
}

bool AES128::encrypt(const QByteArray &in, QByteArray *out, bool pad)
{
	return false;
}

bool AES128::decrypt(const QByteArray &in, QByteArray *out, bool pad)
{
	return false;
}


//----------------------------------------------------------------------------
// AES256
//----------------------------------------------------------------------------
AES256::AES256()
{
}

AES256::~AES256()
{
}

bool AES256::encrypt(const QByteArray &in, QByteArray *out, bool pad)
{
	return false;
}

bool AES256::decrypt(const QByteArray &in, QByteArray *out, bool pad)
{
	return false;
}
*/

