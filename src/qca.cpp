#include"qca.h"

using namespace QCA;

QString arrayToHex(const QByteArray &a)
{
	QString out;
	for(int n = 0; n < (int)a.size(); ++n) {
		QString str;
		str.sprintf("%02x", (uchar)a[n]);
		out.append(str);
	}

	return out;
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
}

SHA1::~SHA1()
{
}

void SHA1::clear()
{
}

void SHA1::update(const QByteArray &a)
{
}

QByteArray SHA1::final()
{
	printf("sha1 finalizing\n");
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
	printf("md5 finalizing\n");
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
