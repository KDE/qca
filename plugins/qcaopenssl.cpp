#include"qcaopenssl.h"

#include<qptrlist.h>
#include<openssl/sha.h>
#include<openssl/md5.h>
#include<openssl/evp.h>
#include<openssl/rsa.h>
#include<openssl/x509.h>

#include<stdlib.h>
static bool seeded = false;
class QRandom
{
public:
	static uchar randomChar();
	static uint randomInt();
	static QByteArray randomArray(uint size);
};

uchar QRandom::randomChar()
{
	if(!seeded) {
		srand(time(NULL));
		seeded = true;
	}
	return rand();
}

uint QRandom::randomInt()
{
	QByteArray a = randomArray(sizeof(uint));
	uint x;
	memcpy(&x, a.data(), a.size());
	return x;
}

QByteArray QRandom::randomArray(uint size)
{
	QByteArray a(size);
	for(uint n = 0; n < size; ++n)
		a[n] = randomChar();
	return a;
}

static bool lib_generateKeyIV(const EVP_CIPHER *type, const QByteArray &data, const QByteArray &salt, QByteArray *key, QByteArray *iv)
{
	QByteArray k, i;
	unsigned char *kp = 0;
	unsigned char *ip = 0;
	if(key) {
		k.resize(type->key_len);
		kp = (unsigned char *)k.data();
	}
	if(iv) {
		i.resize(type->iv_len);
		ip = (unsigned char *)i.data();
	}
	if(!EVP_BytesToKey(type, EVP_sha1(), (unsigned char *)salt.data(), (unsigned char *)data.data(), data.size(), 1, kp, ip))
		return false;
	if(key)
		*key = k;
	if(iv)
		*iv = i;
	return true;
}

static void appendArray(QByteArray *a, const QByteArray &b)
{
	int oldsize = a->size();
	a->resize(oldsize + b.size());
	memcpy(a->data() + oldsize, b.data(), b.size());
}


class SHA1Context : public QCA_HashContext
{
public:
	SHA1Context()
	{
		reset();
	}

	void reset()
	{
		SHA1_Init(&c);
	}

	void update(const char *in, unsigned int len)
	{
		SHA1_Update(&c, in, len);
	}

	void final(char **out, unsigned int *outlen)
	{
		*outlen = 20;
		unsigned char *outbuf = (unsigned char *)malloc(*outlen);
		SHA1_Final(outbuf, &c);
		*out = (char *)outbuf;
	}

	SHA_CTX c;
};

class MD5Context : public QCA_HashContext
{
public:
	MD5Context()
	{
		reset();
	}

	void reset()
	{
		MD5_Init(&c);
	}

	void update(const char *in, unsigned int len)
	{
		MD5_Update(&c, in, len);
	}

	void final(char **out, unsigned int *outlen)
	{
		*outlen = 16;
		unsigned char *outbuf = (unsigned char *)malloc(*outlen);
		MD5_Final(outbuf, &c);
		*out = (char *)outbuf;
	}

	MD5_CTX c;
};

class EVPCipherContext : public QCA_CipherContext
{
public:
	EVPCipherContext()
	{
		type = 0;
	}

	virtual ~EVPCipherContext()
	{
		memset(&c, 0, sizeof(EVP_CIPHER_CTX));
	}

	virtual const EVP_CIPHER *getType(int mode) const=0;

	int keySize() { return 24; }
	int blockSize() { return 8; }

	bool generateKey(char *out)
	{
		QByteArray a;
		if(!lib_generateKeyIV(getType(QCA::CBC), QRandom::randomArray(128), QRandom::randomArray(2), &a, 0))
			return false;
		memcpy(out, a.data(), a.size());
		return true;
	}

	bool generateIV(char *out)
	{
		QByteArray a;
		if(!lib_generateKeyIV(getType(QCA::CBC), QRandom::randomArray(128), QRandom::randomArray(2), 0, &a))
			return false;
		memcpy(out, a.data(), a.size());
		return true;
	}

	bool setup(int _dir, int mode, const char *key, const char *iv)
	{
		dir = _dir;
		type = getType(mode);
		EVP_CIPHER_CTX_init(&c);

		if(dir == QCA::Encrypt) {
			if(!EVP_EncryptInit(&c, type, (unsigned char *)key, (unsigned char *)iv))
				return false;
		}
		else {
			if(!EVP_DecryptInit(&c, type, (unsigned char *)key, (unsigned char *)iv))
				return false;
		}
		return true;
	}

	bool update(const char *in, unsigned int len)
	{
		QByteArray result(len + type->block_size);
		int olen;
		if(dir == QCA::Encrypt) {
			if(!EVP_EncryptUpdate(&c, (unsigned char *)result.data(), &olen, (const unsigned char *)in, len))
				return false;
		}
		else {
			if(!EVP_DecryptUpdate(&c, (unsigned char *)result.data(), &olen, (const unsigned char *)in, len))
				return false;
		}
		result.resize(olen);
		appendArray(&r, result);
		return true;
	}

	bool final(char **out, unsigned int *outlen)
	{
		QByteArray result(type->block_size);
		int olen;
		if(dir == QCA::Encrypt) {
			if(!EVP_EncryptFinal(&c, (unsigned char *)result.data(), &olen))
				return false;
		}
		else {
			if(!EVP_DecryptFinal(&c, (unsigned char *)result.data(), &olen))
				return false;
		}
		result.resize(olen);
		appendArray(&r, result);

		*outlen = r.size();
		unsigned char *outbuf = (unsigned char *)malloc(*outlen);
		*out = (char *)outbuf;
		memcpy(outbuf, r.data(), r.size());
		return true;
	}

	EVP_CIPHER_CTX c;
	const EVP_CIPHER *type;
	QByteArray r;
	int dir;
};

class BlowFishContext : public EVPCipherContext
{
public:
	const EVP_CIPHER *getType(int mode) const
	{
		if(mode == QCA::CBC)
			return EVP_bf_cbc();
		else if(mode == QCA::CFB)
			return EVP_bf_cfb();
		else
			return 0;
	}
};

class TripleDESContext : public EVPCipherContext
{
public:
	const EVP_CIPHER *getType(int mode) const
	{
		if(mode == QCA::CBC)
			return EVP_des_ede3_cbc();
		else if(mode == QCA::CFB)
			return EVP_des_ede3_cfb();
		else
			return 0;
	}
};

class RSAKeyContext : public QCA_RSAKeyContext
{
public:
	RSAKeyContext()
	{
		r = 0;
	}

	~RSAKeyContext()
	{
		if(r)
			RSA_free(r);
	}

	bool isNull() const
	{
		return (r ? false: true);
	}

	bool createFromDER(const char *in, unsigned int len, bool sec)
	{
		RSA *t;
		if(sec) {
			const unsigned char *p = (const unsigned char *)in;
			t = d2i_RSAPrivateKey(NULL, &p, len);
		}
		else {
			unsigned char *p = (unsigned char *)in;
			t = d2i_RSA_PUBKEY(NULL, &p,len);
		}
		if(!t)
			return false;

		r = t;
		return true;
	}

	bool createFromNative(void *in)
	{
		r = (RSA *)in;
		++(r->references);
		return true;
	}

	bool generate(unsigned int bits)
	{
		RSA *t = RSA_generate_key(bits, RSA_F4, NULL, NULL);
		if(!t)
			return false;

		r = t;
		return true;
	}

	QCA_RSAKeyContext *clone()
	{
		RSAKeyContext *c = new RSAKeyContext;
		if(r)
			c->createFromNative(r);
		return c;
	}

	void toDER(char **out, unsigned int *len)
	{
		*out = 0;
		*len = 0;
	}

	bool encrypt(const char *in, unsigned int len, char **out, unsigned int *outlen)
	{
		int size = RSA_size(r);
		int flen = len;
		if(flen >= size - 11)
			flen = size - 11;
		QByteArray result(size);
		unsigned char *from = (unsigned char *)in;
		unsigned char *to = (unsigned char *)result.data();
		int ret = RSA_public_encrypt(flen, from, to, r, RSA_PKCS1_PADDING);
		if(ret == -1)
			return false;
		result.resize(ret);

		*out = (char *)malloc(result.size());
		memcpy((*out), result.data(), result.size());
		*outlen = result.size();
		return true;
	}

	bool decrypt(const char *in, unsigned int len, char **out, unsigned int *outlen)
	{
		int size = RSA_size(r);
		int flen = len;
		QByteArray result(size);
		unsigned char *from = (unsigned char *)in;
		unsigned char *to = (unsigned char *)result.data();
		int ret = RSA_private_decrypt(flen, from, to, r, RSA_PKCS1_PADDING);
		if(ret == -1)
			return false;
		result.resize(ret);

		*out = (char *)malloc(result.size());
		memcpy((*out), result.data(), result.size());
		*outlen = result.size();
		return true;
	}

	RSA *r;
};


class QCAOpenSSL : public QCAProvider
{
public:
	QCAOpenSSL() {}
	~QCAOpenSSL() {}

	int capabilities() const
	{
		return (QCA::CAP_SHA1 | QCA::CAP_MD5 | QCA::CAP_BlowFish | QCA::CAP_TripleDES | QCA::CAP_RSA);
	}

	void *functions(int cap)
	{
		if(cap == QCA::CAP_SHA1)
			return new SHA1Context;
		else if(cap == QCA::CAP_MD5)
			return new MD5Context;
		else if(cap == QCA::CAP_BlowFish)
			return new BlowFishContext;
		else if(cap == QCA::CAP_TripleDES)
			return new TripleDESContext;
		else if(cap == QCA::CAP_RSA)
			return new RSAKeyContext;
		return 0;
	}
};

#ifdef QCA_PLUGIN
QCAProvider *createProvider()
#else
QCAProvider *createProviderOpenSSL()
#endif
{
	return (new QCAOpenSSL);
}
