#include"qca-tls.h"

#include<qregexp.h>

#include<openssl/sha.h>
#include<openssl/md5.h>
#include<openssl/evp.h>
#include<openssl/bio.h>
#include<openssl/pem.h>
#include<openssl/rsa.h>
#include<openssl/x509.h>
#include<openssl/x509v3.h>
#include<openssl/ssl.h>
#include<openssl/err.h>

#ifndef OSSL_097
#define NO_AES
#endif

// FIXME: use openssl for entropy instead of stdlib
// FIXME: handle return value of BIO_new
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

static bool lib_generateKeyIV(const EVP_CIPHER *_type, const QByteArray &data, const QByteArray &salt, QByteArray *key, QByteArray *iv, int keysize=-1)
{
	QByteArray k, i;
	unsigned char *kp = 0;
	unsigned char *ip = 0;
	EVP_CIPHER type = *_type;
	if(keysize != -1)
		type.key_len = keysize;
	if(key) {
		k.resize(type.key_len);
		kp = (unsigned char *)k.data();
	}
	if(iv) {
		i.resize(type.iv_len);
		ip = (unsigned char *)i.data();
	}
	if(!EVP_BytesToKey(&type, EVP_sha1(), (unsigned char *)salt.data(), (unsigned char *)data.data(), data.size(), 1, kp, ip))
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
		if(type) {
			EVP_CIPHER_CTX_cleanup(&c);
			type = 0;
		}
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

	bool generateKey(char *out, int keysize)
	{
		QByteArray a;
		if(!lib_generateKeyIV(getType(QCA::CBC), QRandom::randomArray(128), QRandom::randomArray(2), &a, 0, keysize))
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

	bool setup(int _dir, int mode, const char *key, int keysize, const char *iv, bool _pad)
	{
		dir = _dir;
		pad = _pad;
		type = getType(mode);
		r.resize(0);
		EVP_CIPHER_CTX_init(&c);

		if(dir == QCA::Encrypt) {
			if(!EVP_EncryptInit(&c, type, NULL, NULL))
				return false;
			if(keysize != type->key_len)
				EVP_CIPHER_CTX_set_key_length(&c, keysize);
			if(!EVP_EncryptInit(&c, NULL, (unsigned char *)key, (unsigned char *)iv))
				return false;
		}
		else {
			if(!EVP_DecryptInit(&c, type, NULL, NULL))
				return false;
			if(keysize != type->key_len)
				EVP_CIPHER_CTX_set_key_length(&c, keysize);
			if(!EVP_DecryptInit(&c, NULL, (unsigned char *)key, (unsigned char *)iv))
				return false;
		}
		return true;
	}

	bool update(const char *in, unsigned int len)
	{
		QByteArray result(len + type->block_size);
		int olen;
		if(dir == QCA::Encrypt || !pad) {
			if(!EVP_EncryptUpdate(&c, (unsigned char *)result.data(), &olen, (unsigned char *)in, len))
				return false;
		}
		else {
			if(!EVP_DecryptUpdate(&c, (unsigned char *)result.data(), &olen, (unsigned char *)in, len))
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

#ifndef NO_AES
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
#endif

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
#ifdef OSSL_097
			*pub = d2i_RSAPublicKey(NULL, (const unsigned char **)&p, len);
#else
			*pub = d2i_RSAPublicKey(NULL, (unsigned char **)&p, len);
#endif
			free(buf);
		}

		len = i2d_RSAPrivateKey(r, NULL);
		if(len > 0) {
			buf = (unsigned char *)malloc(len);
			p = buf;
			i2d_RSAPrivateKey(r, &p);
			p = buf;
#ifdef OSSL_097
			*sec = d2i_RSAPrivateKey(NULL, (const unsigned char **)&p, len);
#else
			*sec = d2i_RSAPrivateKey(NULL, (unsigned char **)&p, len);
#endif
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
#ifdef OSSL_097
		r = d2i_RSAPrivateKey(NULL, (const unsigned char **)&p, len);
#else
		r = d2i_RSAPrivateKey(NULL, (unsigned char **)&p, len);
#endif
		if(r) {
			reset();

			// private means both, I think, so separate them
			separate(r, &pub, &sec);
			return true;
		}
		else {
			// public?
			p = (void *)in;
#ifdef OSSL_097
			r = d2i_RSAPublicKey(NULL, (const unsigned char **)&p, len);
#else
			r = d2i_RSAPublicKey(NULL, (unsigned char **)&p, len);
#endif
			if(!r) {
				// try this other public function, for whatever reason
				p = (void *)in;
				r = d2i_RSA_PUBKEY(NULL, (unsigned char **)&p, len);
			}
			if(r) {
				if(pub) {
					RSA_free(pub);
				}
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
				if(pub) {
					RSA_free(pub);
				}
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

	QCA_RSAKeyContext *clone() const
	{
		// deep copy
		RSAKeyContext *c = new RSAKeyContext;
		if(pub) {
			++(pub->references);
			c->pub = pub; //RSAPublicKey_dup(pub);
		}
		if(sec) {
			++(sec->references);
			c->sec = sec; //RSAPrivateKey_dup(sec);
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

// (adapted from kdelibs) -- Justin
static bool cnMatchesAddress(const QString &_cn, const QString &peerHost)
{
	QString cn = _cn.stripWhiteSpace().lower();
	QRegExp rx;

	// Check for invalid characters
	if(QRegExp("[^a-zA-Z0-9\\.\\*\\-]").search(cn) >= 0)
		return false;

	// Domains can legally end with '.'s.  We don't need them though.
	while(cn.endsWith("."))
		cn.truncate(cn.length()-1);

	// Do not let empty CN's get by!!
	if(cn.isEmpty())
		return false;

	// Check for IPv4 address
	rx.setPattern("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}");
	if(rx.exactMatch(peerHost))
		return peerHost == cn;

	// Check for IPv6 address here...
	rx.setPattern("^\\[.*\\]$");
	if(rx.exactMatch(peerHost))
		return peerHost == cn;

	if(cn.contains('*')) {
		// First make sure that there are at least two valid parts
		// after the wildcard (*).
		QStringList parts = QStringList::split('.', cn, false);

		while(parts.count() > 2)
			parts.remove(parts.begin());

		if(parts.count() != 2) {
			return false;  // we don't allow *.root - that's bad
		}

		if(parts[0].contains('*') || parts[1].contains('*')) {
			return false;
		}

		// RFC2818 says that *.example.com should match against
		// foo.example.com but not bar.foo.example.com
		// (ie. they must have the same number of parts)
		if(QRegExp(cn, false, true).exactMatch(peerHost) &&
			QStringList::split('.', cn, false).count() ==
			QStringList::split('.', peerHost, false).count())
			return true;

		return false;
	}

	// We must have an exact match in this case (insensitive though)
	// (note we already did .lower())
	if(cn == peerHost)
		return true;
	return false;
}

class SSLContext;
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

	QCA_CertContext *clone() const
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
		if(x) {
			X509_free(x);
			x = 0;

			serial = "";
			v_subject = "";
			v_issuer = "";
			cp_subject.clear();
			cp_issuer.clear();
			na = QDateTime();
			nb = QDateTime();
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

	bool matchesAddress(const QString &realHost) const
	{
		QString peerHost = realHost.stripWhiteSpace();
		while(peerHost.endsWith("."))
			peerHost.truncate(peerHost.length()-1);
		peerHost = peerHost.lower();

		QString cn;
		for(QValueList<QCA_CertProperty>::ConstIterator it = cp_subject.begin(); it != cp_subject.end(); ++it) {
			if((*it).var == "CN") {
				cn = (*it).val;
				break;
			}
		}
		if(cnMatchesAddress(cn, peerHost))
			return true;
		return false;
	}

	friend class SSLContext;
	X509 *x;
	QString serial, v_subject, v_issuer;
	QValueList<QCA_CertProperty> cp_subject, cp_issuer;
	QDateTime nb, na;
};

static bool ssl_init = false;
class TLSContext : public QCA_TLSContext
{
public:
	enum { Good, TryAgain, Bad };
	enum { Idle, Connect, Accept, Handshake, Active };

	bool serv;
	int mode;
	QByteArray sendQueue, recvQueue;

	CertContext *cert;
	RSAKeyContext *key;

	SSL *ssl;
	SSL_METHOD *method;
	SSL_CTX *context;
	BIO *rbio, *wbio;
	CertContext cc;
	int vr;

	TLSContext()
	{
		if(!ssl_init) {
			SSL_library_init();
			SSL_load_error_strings();
			ssl_init = true;
		}

		ssl = 0;
		context = 0;
		cert = 0;
		key = 0;
	}

	~TLSContext()
	{
		reset();
	}

	void reset()
	{
		if(ssl) {
			SSL_shutdown(ssl);
			SSL_free(ssl);
			ssl = 0;
		}
		if(context) {
			SSL_CTX_free(context);
			context = 0;
		}
		if(cert) {
			delete cert;
			cert = 0;
		}
		if(key) {
			delete key;
			key = 0;
		}

		sendQueue.resize(0);
		recvQueue.resize(0);
		mode = Idle;
		cc.reset();
		vr = QCA::TLS::Unknown;
	}

	bool startClient(const QPtrList<QCA_CertContext> &store, const QCA_CertContext &cert, const QCA_RSAKeyContext &key)
	{
		reset();
		serv = false;
		method = SSLv23_client_method();

		if(!setup(store, cert, key))
			return false;

		mode = Connect;
		return true;
	}

	bool startServer(const QPtrList<QCA_CertContext> &store, const QCA_CertContext &cert, const QCA_RSAKeyContext &key)
	{
		reset();
		serv = true;
		method = SSLv23_server_method();

		if(!setup(store, cert, key))
			return false;

		mode = Accept;
		return true;
	}

	bool setup(const QPtrList<QCA_CertContext> &list, const QCA_CertContext &cc, const QCA_RSAKeyContext &kc)
	{
		context = SSL_CTX_new(method);
		if(!context) {
			reset();
			return false;
		}

		// load the cert store
		if(!list.isEmpty()) {
			X509_STORE *store = SSL_CTX_get_cert_store(context);
			QPtrListIterator<QCA_CertContext> it(list);
			for(CertContext *cc; (cc = (CertContext *)it.current()); ++it)
				X509_STORE_add_cert(store, cc->x);
		}

		ssl = SSL_new(context);
		if(!ssl) {
			reset();
			return false;
		}
		SSL_set_ssl_method(ssl, method); // can this return error?

		// setup the memory bio
		rbio = BIO_new(BIO_s_mem());
		wbio = BIO_new(BIO_s_mem());

		// this passes control of the bios to ssl.  we don't need to free them.
		SSL_set_bio(ssl, rbio, wbio);

		// setup the cert to send
		if(!cc.isNull() && !kc.isNull()) {
			cert = static_cast<CertContext*>(cc.clone());
			key = static_cast<RSAKeyContext*>(kc.clone());
			if(SSL_use_certificate(ssl, cert->x) != 1) {
				reset();
				return false;
			}
			if(SSL_use_RSAPrivateKey(ssl, key->sec) != 1) {
				reset();
				return false;
			}
		}

		return true;
	}

	int handshake(const QByteArray &in, QByteArray *out)
	{
		if(!in.isEmpty())
			BIO_write(rbio, in.data(), in.size());

		if(mode == Connect) {
			int ret = doConnect();
			if(ret == Good) {
				mode = Handshake;
			}
			else if(ret == Bad) {
				reset();
				return Error;
			}
		}

		if(mode == Accept) {
			int ret = doAccept();
			if(ret == Good) {
				getCert();
				mode = Active;
			}
			else if(ret == Bad) {
				reset();
				return Error;
			}
		}

		if(mode == Handshake) {
			int ret = doHandshake();
			if(ret == Good) {
				getCert();
				mode = Active;
			}
			else if(ret == Bad) {
				reset();
				return Error;
			}
		}

		// process outgoing
		*out = readOutgoing();

		if(mode == Active)
			return Success;
		else
			return Continue;
	}

	void getCert()
	{
		// verify the certificate
		int code = QCA::TLS::Unknown;
		X509 *x = SSL_get_peer_certificate(ssl);
		if(x) {
			cc.fromX509(x);
			X509_free(x);
			int ret = SSL_get_verify_result(ssl);
			if(ret == X509_V_OK)
				code = QCA::TLS::Valid;
			else
				code = resultToCV(ret);
		}
		else {
			cc.reset();
			code = QCA::TLS::NoCert;
		}
		vr = code;
	}

	bool encode(const QByteArray &plain, QByteArray *to_net)
	{
		if(mode != Active)
			return false;
		appendArray(&sendQueue, plain);

		if(sendQueue.size() > 0) {
			// since we are using memory BIOs, the whole thing can be written successfully
			SSL_write(ssl, sendQueue.data(), sendQueue.size());
			// TODO: error?
			sendQueue.resize(0);
		}

		*to_net = readOutgoing();
		return true;
	}

	bool decode(const QByteArray &from_net, QByteArray *plain, QByteArray *to_net)
	{
		if(mode != Active)
			return false;
		if(!from_net.isEmpty())
			BIO_write(rbio, from_net.data(), from_net.size());

		QByteArray a;
		while(1) {
			a.resize(4096);
			int x = SSL_read(ssl, a.data(), a.size());
			if(x <= 0)
				break;
			if(x != (int)a.size())
				a.resize(x);
			appendArray(&recvQueue, a);
		}

		*plain = recvQueue.copy();
		recvQueue.resize(0);

		// could be outgoing data also
		*to_net = readOutgoing();
		return true;
	}

	QByteArray readOutgoing()
	{
		QByteArray a;
		int size = BIO_pending(wbio);
		if(size <= 0)
			return a;
		a.resize(size);

		int r = BIO_read(wbio, a.data(), size);
		if(r <= 0) {
			a.resize(0);
			return a;
		}
		if(r != size)
			a.resize(r);
		return a;
	}

	int doConnect()
	{
		int ret = SSL_connect(ssl);
		if(ret < 0) {
			int x = SSL_get_error(ssl, ret);
			if(x == SSL_ERROR_WANT_CONNECT || x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
				return TryAgain;
			else
				return Bad;
		}
		else if(ret == 0)
			return Bad;
		return Good;
	}

	int doAccept()
	{
		int ret = SSL_accept(ssl);
		if(ret < 0) {
			int x = SSL_get_error(ssl, ret);
			if(x == SSL_ERROR_WANT_CONNECT || x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
				return TryAgain;
			else
				return Bad;
		}
		else if(ret == 0)
			return Bad;
		return Good;
	}

	int doHandshake()
	{
		int ret = SSL_do_handshake(ssl);
		if(ret < 0) {
			int x = SSL_get_error(ssl, ret);
			if(x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
				return TryAgain;
			else
				return Bad;
		}
		else if(ret == 0)
			return Bad;
		return Good;
	}

	QCA_CertContext *peerCertificate() const
	{
		return cc.clone();
	}

	int validityResult() const
	{
		return vr;
	}

	int resultToCV(int ret) const
	{
		int rc;

		switch(ret) {
			case X509_V_ERR_CERT_REJECTED:
				rc = QCA::TLS::Rejected;
				break;
			case X509_V_ERR_CERT_UNTRUSTED:
				rc = QCA::TLS::Untrusted;
				break;
			case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
			case X509_V_ERR_CERT_SIGNATURE_FAILURE:
			case X509_V_ERR_CRL_SIGNATURE_FAILURE:
			case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
			case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
				rc = QCA::TLS::SignatureFailed;
				break;
			case X509_V_ERR_INVALID_CA:
			case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
			case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
				rc = QCA::TLS::InvalidCA;
				break;
			case X509_V_ERR_INVALID_PURPOSE:
				rc = QCA::TLS::InvalidPurpose;
				break;
			case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
				rc = QCA::TLS::SelfSigned;
				break;
			case X509_V_ERR_CERT_REVOKED:
				rc = QCA::TLS::Revoked;
				break;
			case X509_V_ERR_PATH_LENGTH_EXCEEDED:
				rc = QCA::TLS::PathLengthExceeded;
				break;
			case X509_V_ERR_CERT_NOT_YET_VALID:
			case X509_V_ERR_CERT_HAS_EXPIRED:
			case X509_V_ERR_CRL_NOT_YET_VALID:
			case X509_V_ERR_CRL_HAS_EXPIRED:
			case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
			case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
				rc = QCA::TLS::Expired;
				break;
			case X509_V_ERR_APPLICATION_VERIFICATION:
			case X509_V_ERR_OUT_OF_MEM:
			case X509_V_ERR_UNABLE_TO_GET_CRL:
			case X509_V_ERR_CERT_CHAIN_TOO_LONG:
			default:
				rc = QCA::TLS::Unknown;
				break;
		}
		return rc;
	}
};

class QCAOpenSSL : public QCAProvider
{
public:
	QCAOpenSSL() {}
	~QCAOpenSSL() {}

	int capabilities() const
	{
		int caps =
			QCA::CAP_SHA1 |
			QCA::CAP_MD5 |
			QCA::CAP_BlowFish |
			QCA::CAP_TripleDES |
#ifndef NO_AES
			QCA::CAP_AES128 |
			QCA::CAP_AES256 |
#endif
			QCA::CAP_RSA |
			QCA::CAP_X509 |
			QCA::CAP_TLS;
		return caps;
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
#ifndef NO_AES
		else if(cap == QCA::CAP_AES128)
			return new AES128Context;
		else if(cap == QCA::CAP_AES256)
			return new AES256Context;
#endif
		else if(cap == QCA::CAP_RSA)
			return new RSAKeyContext;
		else if(cap == QCA::CAP_X509)
			return new CertContext;
		else if(cap == QCA::CAP_TLS)
			return new TLSContext;
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

//#include"qcaopenssl.moc"
