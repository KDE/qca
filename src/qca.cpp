#include"qca.h"

#include<qptrlist.h>
#include"qcaprovider.h"
#include<stdio.h>

#ifdef USE_OPENSSL
#include"qcaopenssl_p.h"
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
	if(!f) {
		printf("SHA1: can't initialize!\n");
		return;
	}

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
	printf("sha256 finalizing\n");
	return QByteArray();
}


//----------------------------------------------------------------------------
// MD5
//----------------------------------------------------------------------------
MD5::MD5()
{
	printf("MD5: initialized\n");
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
