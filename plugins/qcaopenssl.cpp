#include"qcaopenssl.h"

#include<openssl/sha.h>
#include<openssl/md5.h>
#include<openssl/evp.h>
#include<openssl/bio.h>
#include<openssl/pem.h>
#include<openssl/rsa.h>
#include<openssl/x509.h>
#include<openssl/x509v3.h>

// FIXME: use openssl for entropy instead of stdlib
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

static char *bio2buf(BIO *b, unsigned int *len)
{
	char *buf = (char *)malloc(1);
	int size = 0;
	while(1) {
		char block[1024];
		int ret = BIO_read(b, block, 1024);
		buf = (char *)realloc(buf, size + ret);
		memcpy(buf + size, block, ret);
		size += ret;
		if(ret != 1024)
			break;
	}
	BIO_free(b);

	*len = size;
	return buf;
}

class SHA1Context : public QCA_HashContext
{
public:
	SHA1Context()
	{
		reset();
	}

	QCA_HashContext *clone()
	{
		return new SHA1Context(*this);
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

	QCA_HashContext *clone()
	{
		return new MD5Context(*this);
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

	QCA_CipherContext *clone()
	{
		EVPCipherContext *c = cloneSelf();
		c->r = r.copy();
		return c;
	}

	virtual EVPCipherContext *cloneSelf() const=0;
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
	EVPCipherContext *cloneSelf() const { return new BlowFishContext(*this); }
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
	EVPCipherContext *cloneSelf() const { return new TripleDESContext(*this); }
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
	EVPCipherContext *cloneSelf() const { return new AES128Context(*this); }
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
	EVPCipherContext *cloneSelf() const { return new AES256Context(*this); }
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

		*out = bio2buf(bo, outlen);
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

static QValueList<QCA_CertProperty> nameToProperties(X509_NAME *name)
{
	QValueList<QCA_CertProperty> list;

	for(int n = 0; n < X509_NAME_entry_count(name); ++n) {
		X509_NAME_ENTRY *ne = X509_NAME_get_entry(name, n);
		QCA_CertProperty p;

		ASN1_OBJECT *ao = X509_NAME_ENTRY_get_object(ne);
		int nid = OBJ_obj2nid(ao);
		if(nid == NID_undef)
			continue;
		p.var = OBJ_nid2sn(nid);

		ASN1_STRING *as = X509_NAME_ENTRY_get_data(ne);
		QCString c;
		c.resize(as->length+1);
		strncpy(c.data(), (char *)as->data, as->length);
		p.val = QString::fromLatin1(c);
		list += p;
	}

	return list;
}

// (taken from kdelibs) -- Justin
//
// This code is mostly taken from OpenSSL v0.9.5a
// by Eric Young
QDateTime ASN1_UTCTIME_QDateTime(ASN1_UTCTIME *tm, int *isGmt)
{
	QDateTime qdt;
	char *v;
	int gmt=0;
	int i;
	int y=0,M=0,d=0,h=0,m=0,s=0;
	QDate qdate;
	QTime qtime;

	i = tm->length;
	v = (char *)tm->data;

	if (i < 10) goto auq_err;
	if (v[i-1] == 'Z') gmt=1;
	for (i=0; i<10; i++)
		if ((v[i] > '9') || (v[i] < '0')) goto auq_err;
	y = (v[0]-'0')*10+(v[1]-'0');
	if (y < 50) y+=100;
	M = (v[2]-'0')*10+(v[3]-'0');
	if ((M > 12) || (M < 1)) goto auq_err;
	d = (v[4]-'0')*10+(v[5]-'0');
	h = (v[6]-'0')*10+(v[7]-'0');
	m =  (v[8]-'0')*10+(v[9]-'0');
	if (    (v[10] >= '0') && (v[10] <= '9') &&
		(v[11] >= '0') && (v[11] <= '9'))
		s = (v[10]-'0')*10+(v[11]-'0');

	// localize the date and display it.
	qdate.setYMD(y+1900, M, d);
	qtime.setHMS(h,m,s);
	qdt.setDate(qdate); qdt.setTime(qtime);
auq_err:
	if (isGmt) *isGmt = gmt;
	return qdt;
}

class CertContext : public QCA_CertContext
{
public:
	CertContext()
	{
		x = 0;
	}

	~CertContext()
	{
		reset();
	}

	QCA_CertContext *clone()
	{
		CertContext *c = new CertContext(*this);
		if(x) {
			++(x->references);
			c->x = x;
		}
		return c;
	}

	void reset()
	{
		serial = "";
		v_subject = "";
		v_issuer = "";
		cp_subject.clear();
		cp_issuer.clear();
		na = QDateTime();
		nb = QDateTime();
		if(x) {
			X509_free(x);
			x = 0;
		}
	}

	bool isNull() const
	{
		return (x ? false: true);
	}

	bool createFromDER(const char *in, unsigned int len)
	{
		unsigned char *p = (unsigned char *)in;
		X509 *t = d2i_X509(NULL, &p, len);
		if(!t)
			return false;
		fromX509(t);
		return true;
	}

	bool createFromPEM(const char *in, unsigned int len)
	{
		BIO *bi = BIO_new(BIO_s_mem());
		BIO_write(bi, in, len);
		X509 *t = PEM_read_bio_X509(bi, NULL, NULL, NULL);
		BIO_free(bi);
		if(!t)
			return false;
		fromX509(t);
		return true;
	}

	void toDER(char **out, unsigned int *outlen)
	{
		int len = i2d_X509(x, NULL);
		unsigned char *buf, *p;
		buf = (unsigned char *)malloc(len);
		p = buf;
		i2d_X509(x, &p);
		*out = (char *)buf;
		*outlen = len;
	}

	void toPEM(char **out, unsigned int *outlen)
	{
		BIO *bo = BIO_new(BIO_s_mem());
		PEM_write_bio_X509(bo, x);
		*out = bio2buf(bo, outlen);
	}

	void fromX509(X509 *t)
	{
		reset();
		++(t->references);
		x = t;

		// serial number
		ASN1_INTEGER *ai = X509_get_serialNumber(x);
		if(ai) {
			char *rep = i2s_ASN1_INTEGER(NULL, ai);
			serial = rep;
			OPENSSL_free(rep);
		}

		// validity dates
		nb = ASN1_UTCTIME_QDateTime(X509_get_notBefore(x), NULL);
		na = ASN1_UTCTIME_QDateTime(X509_get_notAfter(x), NULL);

		// extract the subject/issuer strings
		X509_NAME *sn = X509_get_subject_name(x);
		X509_NAME *in = X509_get_issuer_name(x);
		char buf[1024];
		X509_NAME_oneline(sn, buf, 1024);
		v_subject = buf;
		X509_NAME_oneline(in, buf, 1024);
		v_issuer = buf;

		// extract the subject/issuer contents
		cp_subject = nameToProperties(sn);
		cp_issuer  = nameToProperties(in);
	}

	QString serialNumber() const
	{
		return serial;
	}

	QString subjectString() const
	{
		return v_subject;
	}

	QString issuerString() const
	{
		return v_issuer;
	}

	QValueList<QCA_CertProperty> subject() const
	{
		return cp_subject;
	}

	QValueList<QCA_CertProperty> issuer() const
	{
		return cp_issuer;
	}

	QDateTime notBefore() const
	{
		return nb;
	}

	QDateTime notAfter() const
	{
		return na;
	}

	X509 *x;
	QString serial, v_subject, v_issuer;
	QValueList<QCA_CertProperty> cp_subject, cp_issuer;
	QDateTime nb, na;
};

class QCAOpenSSL : public QCAProvider
{
public:
	QCAOpenSSL() {}
	~QCAOpenSSL() {}

	int capabilities() const
	{
		return (QCA::CAP_SHA1 | QCA::CAP_MD5 | QCA::CAP_BlowFish | QCA::CAP_TripleDES | QCA::CAP_AES128 | QCA::CAP_AES256 | QCA::CAP_RSA | QCA::CAP_X509);
	}

	void *context(int cap)
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
		else if(cap == QCA::CAP_X509)
			return new CertContext;
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
