#include"qca.h"

#include<qptrlist.h>
#include"qcaprovider.h"
#include<stdio.h>

#define USE_OPENSSL

#ifdef USE_OPENSSL
#include"qcaopenssl.h"
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
	providerList.append(new QCAOpenSSL);
#endif
}

bool QCA::isSupported(int capabilities)
{
	int caps = 0;
	QPtrListIterator<QCAProvider> it(providerList);
	for(QCAProvider *p; (p = it.current()); ++it)
		caps |= p->capabilities();
	return caps;
}

static QCAProvider * getp(int cap)
{
	QPtrListIterator<QCAProvider> it(providerList);
	for(QCAProvider *p; (p = it.current()); ++it) {
		if(p->capabilities() & cap)
			return p;
	}
	return 0;
}


//----------------------------------------------------------------------------
// Hash
//----------------------------------------------------------------------------
Hash::Hash()
{
	p = 0;
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
	p = getp(CAP_SHA1);
	if(!p) {
		printf("SHA1: can't initialize!\n");
		return;
	}

	ctx = p->sha1_create();
}

SHA1::~SHA1()
{
	p->sha1_destroy(ctx);
}

void SHA1::clear()
{
	p->sha1_destroy(ctx);
	ctx = p->sha1_create();
}

void SHA1::update(const QByteArray &a)
{
	p->sha1_update(ctx, a.data(), a.size());
}

QByteArray SHA1::final()
{
	QByteArray buf(20);
	p->sha1_final(ctx, buf.data());
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
}

bool TripleDES::decrypt(const QByteArray &in, QByteArray *out, bool pad)
{
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
}

bool AES128::decrypt(const QByteArray &in, QByteArray *out, bool pad)
{
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
}

bool AES256::decrypt(const QByteArray &in, QByteArray *out, bool pad)
{
}
