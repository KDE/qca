#include"qcaopenssl.h"

#include<qptrlist.h>
#include<openssl/sha.h>
#include<openssl/md5.h>
#include<openssl/evp.h>
#include<openssl/bio.h>
#include<openssl/pem.h>
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

	int keySize() { return getType(QCA::CBC)->key_len; }
	int blockSize() { return getType(QCA::CBC)->block_size; }

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

	bool setup(int _dir, int mode, const char *key, const char *iv, bool _pad)
	{
		dir = _dir;
		pad = _pad;
		type = getType(mode);
		r.resize(0);
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
		if(dir == QCA::Encrypt || !pad) {
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
		if(pad) {
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
		}

		*outlen = r.size();
		unsigned char *outbuf = (unsigned char *)malloc(*outlen);
		*out = (char *)outbuf;
		memcpy(outbuf, r.data(), r.size());

		r.resize(0);
		return true;
	}

	EVP_CIPHER_CTX c;
	const EVP_CIPHER *type;
	QByteArray r;
	int dir;
	bool pad;
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

class AES128Context : public EVPCipherContext
{
public:
	const EVP_CIPHER *getType(int mode) const
	{
		if(mode == QCA::CBC)
			return EVP_aes_128_cbc();
		else if(mode == QCA::CFB)
			return EVP_aes_128_cfb();
		else
			return 0;
	}
};

class AES256Context : public EVPCipherContext
{
public:
	const EVP_CIPHER *getType(int mode) const
	{
		if(mode == QCA::CBC)
			return EVP_aes_256_cbc();
		else if(mode == QCA::CFB)
			return EVP_aes_256_cfb();
		else
			return 0;
	}
};

class RSAKeyContext : public QCA_RSAKeyContext
{
public:
	RSAKeyContext()
	{
		pub = 0;
		sec = 0;
	}

	~RSAKeyContext()
	{
		reset();
	}

	void reset()
	{
		if(pub) {
			RSA_free(pub);
			pub = 0;
		}
		if(sec) {
			RSA_free(sec);
			sec = 0;
		}
	}

	void separate(RSA *r, RSA **pub, RSA **sec)
	{
		// public
		unsigned char *buf, *p;
		int len = i2d_RSAPublicKey(r, NULL);
		if(len > 0) {
			buf = (unsigned char *)malloc(len);
			p = buf;
			i2d_RSAPublicKey(r, &p);
			p = buf;
			*pub = d2i_RSAPublicKey(NULL, (const unsigned char **)&p, len);
			free(buf);
		}

		len = i2d_RSAPrivateKey(r, NULL);
		if(len > 0) {
			buf = (unsigned char *)malloc(len);
			p = buf;
			i2d_RSAPrivateKey(r, &p);
			p = buf;
			*sec = d2i_RSAPrivateKey(NULL, (const unsigned char **)&p, len);
			free(buf);
		}
	}

	bool isNull() const
	{
		if(!pub && !sec)
			return true;
		return false;
	}

	bool havePublic() const
	{
		return pub ? true : false;
	}

	bool havePrivate() const
	{
		return sec ? true : false;
	}

	bool createFromDER(const char *in, unsigned int len)
	{
		RSA *r;
		void *p;

		// private?
		p = (void *)in;
		r = d2i_RSAPrivateKey(NULL, (const unsigned char **)&p, len);
		if(r) {
			reset();

			// private means both, I think, so separate them
			separate(r, &pub, &sec);
			return true;
		}
		else {
			// public?
			p = (void *)in;
			r = d2i_RSAPublicKey(NULL, (const unsigned char **)&p, len);
			if(!r) {
				// try this other public function, for whatever reason
				p = (void *)in;
				r = d2i_RSA_PUBKEY(NULL, (unsigned char **)&p, len);
			}
			if(r) {
				if(pub)
					RSA_free(pub);
				pub = r;
				return true;
			}
		}

		return false;
	}

	bool createFromPEM(const char *in, unsigned int len)
	{
		BIO *bi;

		// private?
		bi = BIO_new(BIO_s_mem());
		BIO_write(bi, in, len);
		RSA *r = PEM_read_bio_RSAPrivateKey(bi, NULL, NULL, NULL);
		BIO_free(bi);
		if(r) {
			reset();
			separate(r, &pub, &sec);
			return true;
		}
		else {
			// public?
			bi = BIO_new(BIO_s_mem());
			BIO_write(bi, in, len);
			r = PEM_read_bio_RSAPublicKey(bi, NULL, NULL, NULL);
			BIO_free(bi);
			if(r) {
				if(pub)
					RSA_free(pub);
				pub = r;
				return true;
			}
		}

		return false;
	}

	bool createFromNative(void *in)
	{
		reset();
		separate((RSA *)in, &pub, &sec);
		return true;
	}

	bool generate(unsigned int bits)
	{
		RSA *r = RSA_generate_key(bits, RSA_F4, NULL, NULL);
		if(!r)
			return false;
		separate(r, &pub, &sec);
		RSA_free(r);
		return true;
	}

	QCA_RSAKeyContext *clone()
	{
		RSAKeyContext *c = new RSAKeyContext;
		if(pub) {
			++(pub->references);
			c->pub = pub;
		}
		if(sec) {
			++(sec->references);
			c->sec = sec;
		}
		return c;
	}

	void toDER(char **out, unsigned int *outlen, bool publicOnly)
	{
		if(sec && !publicOnly) {
			int len = i2d_RSAPrivateKey(sec, NULL);
			unsigned char *buf, *p;
			buf = (unsigned char *)malloc(len);
			p = buf;
			i2d_RSAPrivateKey(sec, &p);
			*out = (char *)buf;
			*outlen = len;
		}
		else if(pub) {
			int len = i2d_RSAPublicKey(pub, NULL);
			unsigned char *buf, *p;
			buf = (unsigned char *)malloc(len);
			p = buf;
			i2d_RSAPublicKey(pub, &p);
			*out = (char *)buf;
			*outlen = len;
		}
		else {
			*out = 0;
			*outlen = 0;
		}
	}

	void toPEM(char **out, unsigned int *outlen, bool publicOnly)
	{
		BIO *bo;
		if(sec && !publicOnly) {
			bo = BIO_new(BIO_s_mem());
			PEM_write_bio_RSAPrivateKey(bo, sec, NULL, NULL, 0, NULL, NULL);
		}
		else if(pub) {
			bo = BIO_new(BIO_s_mem());
			PEM_write_bio_RSAPublicKey(bo, pub);
		}
		else {
			*out = 0;
			*outlen = 0;
			return;
		}

		char *buf = (char *)malloc(1);
		int size = 0;
		while(1) {
			char block[1024];
			int ret = BIO_read(bo, block, 1024);
			buf = (char *)realloc(buf, size + ret);
			memcpy(buf + size, block, ret);
			size += ret;
			if(ret != 1024)
				break;
		}
		BIO_free(bo);
		*out = buf;
		*outlen = size;
	}

	bool encrypt(const char *in, unsigned int len, char **out, unsigned int *outlen, bool oaep)
	{
		if(!pub)
			return false;

		int size = RSA_size(pub);
		int flen = len;
		if(oaep) {
			if(flen >= size - 41)
				flen = size - 41;
		}
		else {
			if(flen >= size - 11)
				flen = size - 11;
		}
		QByteArray result(size);
		unsigned char *from = (unsigned char *)in;
		unsigned char *to = (unsigned char *)result.data();
		int ret = RSA_public_encrypt(flen, from, to, pub, oaep ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING);
		if(ret == -1)
			return false;
		result.resize(ret);

		*out = (char *)malloc(result.size());
		memcpy((*out), result.data(), result.size());
		*outlen = result.size();
		return true;
	}

	bool decrypt(const char *in, unsigned int len, char **out, unsigned int *outlen, bool oaep)
	{
		if(!sec)
			return false;

		int size = RSA_size(sec);
		int flen = len;
		QByteArray result(size);
		unsigned char *from = (unsigned char *)in;
		unsigned char *to = (unsigned char *)result.data();
		int ret = RSA_private_decrypt(flen, from, to, sec, oaep ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING);
		if(ret == -1)
			return false;
		result.resize(ret);

		*out = (char *)malloc(result.size());
		memcpy((*out), result.data(), result.size());
		*outlen = result.size();
		return true;
	}

	RSA *pub, *sec;
};


class QCAOpenSSL : public QCAProvider
{
public:
	QCAOpenSSL() {}
	~QCAOpenSSL() {}

	int capabilities() const
	{
		return (QCA::CAP_SHA1 | QCA::CAP_MD5 | QCA::CAP_BlowFish | QCA::CAP_TripleDES | QCA::CAP_AES128 | QCA::CAP_AES256 | QCA::CAP_RSA);
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
		else if(cap == QCA::CAP_AES128)
			return new AES128Context;
		else if(cap == QCA::CAP_AES256)
			return new AES256Context;
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
