/*
 * qca-tls.cpp - TLS plugin for QCA
 * Copyright (C) 2003  Justin Karneges
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

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
#include<openssl/rand.h>

#ifndef OSSL_097
#define NO_AES
#endif

static QByteArray lib_randomArray(int size)
{
	if(RAND_status() == 0) {
		srand(time(NULL));
		char buf[128];
		for(int n = 0; n < 128; ++n)
			buf[n] = rand();
		RAND_seed(buf, 128);
	}
	QByteArray a(size);
	RAND_bytes((unsigned char *)a.data(), a.size());
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

static QByteArray bio2buf(BIO *b)
{
	QByteArray buf;
	while(1) {
		char block[1024];
		int ret = BIO_read(b, block, 1024);
		int oldsize = buf.size();
		buf.resize(oldsize + ret);
		memcpy(buf.data() + oldsize, block, ret);
		if(ret != 1024)
			break;
	}
	BIO_free(b);
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

	void final(QByteArray *out)
	{
		QByteArray buf(20);
		SHA1_Final((unsigned char *)buf.data(), &c);
		*out = buf;
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

	void final(QByteArray *out)
	{
		QByteArray buf(16);
		MD5_Final((unsigned char *)buf.data(), &c);
		*out = buf;
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
		EVPCipherContext *cc = cloneSelf();
		cc->r = r.copy();
		return cc;
	}

	virtual EVPCipherContext *cloneSelf() const=0;
	virtual const EVP_CIPHER *getType(int mode) const=0;

	int keySize() { return getType(QCA::CBC)->key_len; }
	int blockSize() { return getType(QCA::CBC)->block_size; }

	bool generateKey(char *out, int keysize)
	{
		QByteArray a;
		if(!lib_generateKeyIV(getType(QCA::CBC), lib_randomArray(128), lib_randomArray(2), &a, 0, keysize))
			return false;
		memcpy(out, a.data(), a.size());
		return true;
	}

	bool generateIV(char *out)
	{
		QByteArray a;
		if(!lib_generateKeyIV(getType(QCA::CBC), lib_randomArray(128), lib_randomArray(2), 0, &a))
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

	bool final(QByteArray *out)
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

		*out = r.copy();
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

	void separate(RSA *r, RSA **_pub, RSA **_sec)
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
			*_pub = d2i_RSAPublicKey(NULL, (const unsigned char **)&p, len);
#else
			*_pub = d2i_RSAPublicKey(NULL, (unsigned char **)&p, len);
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
			*_sec = d2i_RSAPrivateKey(NULL, (const unsigned char **)&p, len);
#else
			*_sec = d2i_RSAPrivateKey(NULL, (unsigned char **)&p, len);
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

	bool toDER(QByteArray *out, bool publicOnly)
	{
		if(sec && !publicOnly) {
			int len = i2d_RSAPrivateKey(sec, NULL);
			QByteArray buf(len);
			unsigned char *p;
			p = (unsigned char *)buf.data();
			i2d_RSAPrivateKey(sec, &p);
			*out = buf;
			return true;
		}
		else if(pub) {
			int len = i2d_RSAPublicKey(pub, NULL);
			QByteArray buf(len);
			unsigned char *p;
			p = (unsigned char *)buf.data();
			i2d_RSAPublicKey(pub, &p);
			*out = buf;
			return true;
		}
		else
			return false;
	}

	bool toPEM(QByteArray *out, bool publicOnly)
	{
		if(sec && !publicOnly) {
			BIO *bo = BIO_new(BIO_s_mem());
			PEM_write_bio_RSAPrivateKey(bo, sec, NULL, NULL, 0, NULL, NULL);
			*out = bio2buf(bo);
			return true;
		}
		else if(pub) {
			BIO *bo = BIO_new(BIO_s_mem());
			PEM_write_bio_RSAPublicKey(bo, pub);
			*out = bio2buf(bo);
			return true;
		}
		else
			return false;

	}

	bool encrypt(const QByteArray &in, QByteArray *out, bool oaep)
	{
		if(!pub)
			return false;

		int size = RSA_size(pub);
		int flen = in.size();
		if(oaep) {
			if(flen >= size - 41)
				flen = size - 41;
		}
		else {
			if(flen >= size - 11)
				flen = size - 11;
		}
		QByteArray result(size);
		unsigned char *from = (unsigned char *)in.data();
		unsigned char *to = (unsigned char *)result.data();
		int ret = RSA_public_encrypt(flen, from, to, pub, oaep ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING);
		if(ret == -1)
			return false;
		result.resize(ret);

		*out = result;
		return true;
	}

	bool decrypt(const QByteArray &in, QByteArray *out, bool oaep)
	{
		if(!sec)
			return false;

		int size = RSA_size(sec);
		int flen = in.size();
		QByteArray result(size);
		unsigned char *from = (unsigned char *)in.data();
		unsigned char *to = (unsigned char *)result.data();
		int ret = RSA_private_decrypt(flen, from, to, sec, oaep ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING);
		if(ret == -1)
			return false;
		result.resize(ret);

		*out = result;
		return true;
	}

	RSA *pub, *sec;
};

static QValueList<QCA_CertProperty> nameToProperties(struct X509_name_st *name)
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

	bool toDER(QByteArray *out)
	{
		int len = i2d_X509(x, NULL);
		QByteArray buf(len);
		unsigned char *p = (unsigned char *)buf.data();
		i2d_X509(x, &p);
		*out = buf;
		return true;
	}

	bool toPEM(QByteArray *out)
	{
		BIO *bo = BIO_new(BIO_s_mem());
		PEM_write_bio_X509(bo, x);
		*out = bio2buf(bo);
		return true;
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
		struct X509_name_st *sn = X509_get_subject_name(x);
		struct X509_name_st *in = X509_get_issuer_name(x);
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
	enum { Idle, Connect, Accept, Handshake, Active, Closing };

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
	bool v_eof;

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
		v_eof = false;
	}

	bool eof() const
	{
		return v_eof;
	}

	bool startClient(const QPtrList<QCA_CertContext> &store, const QCA_CertContext &_cert, const QCA_RSAKeyContext &_key)
	{
		reset();
		serv = false;
		method = SSLv23_client_method();

		if(!setup(store, _cert, _key))
			return false;

		mode = Connect;
		return true;
	}

	bool startServer(const QPtrList<QCA_CertContext> &store, const QCA_CertContext &_cert, const QCA_RSAKeyContext &_key)
	{
		reset();
		serv = true;
		method = SSLv23_server_method();

		if(!setup(store, _cert, _key))
			return false;

		mode = Accept;
		return true;
	}

	bool setup(const QPtrList<QCA_CertContext> &list, const QCA_CertContext &_cc, const QCA_RSAKeyContext &kc)
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
		if(!_cc.isNull() && !kc.isNull()) {
			cert = static_cast<CertContext*>(_cc.clone());
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

	int shutdown(const QByteArray &in, QByteArray *out)
	{
		if(!in.isEmpty())
			BIO_write(rbio, in.data(), in.size());

		int ret = doShutdown();
		if(ret == Bad) {
			reset();
			return Error;
		}

		*out = readOutgoing();

		if(ret == Good) {
			mode = Idle;
			return Success;
		}
		else {
			mode = Closing;
			return Continue;
		}
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

	bool encode(const QByteArray &plain, QByteArray *to_net, int *enc)
	{
		if(mode != Active)
			return false;
		appendArray(&sendQueue, plain);

		int encoded = 0;
		if(sendQueue.size() > 0) {
			int ret = SSL_write(ssl, sendQueue.data(), sendQueue.size());

			enum { Good, Continue, Done, Error };
			int m;
			if(ret <= 0) {
				int x = SSL_get_error(ssl, ret);
				if(x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
					m = Continue;
				else if(x == SSL_ERROR_ZERO_RETURN)
					m = Done;
				else
					m = Error;
			}
			else {
				m = Good;
				encoded = ret;
				int newsize = sendQueue.size() - encoded;
				char *r = sendQueue.data();
				memmove(r, r + encoded, newsize);
				sendQueue.resize(newsize);
			}

			if(m == Done) {
				sendQueue.resize(0);
				v_eof = true;
				return false;
			}
			if(m == Error) {
				sendQueue.resize(0);
				return false;
			}
		}

		*to_net = readOutgoing();
		*enc = encoded;
		return true;
	}

	bool decode(const QByteArray &from_net, QByteArray *plain, QByteArray *to_net)
	{
		if(mode != Active)
			return false;
		if(!from_net.isEmpty())
			BIO_write(rbio, from_net.data(), from_net.size());

		QByteArray a;
		while(!v_eof) {
			a.resize(8192);
			int ret = SSL_read(ssl, a.data(), a.size());
			if(ret > 0) {
				if(ret != (int)a.size())
					a.resize(ret);
				appendArray(&recvQueue, a);
			}
			else if(ret <= 0) {
				int x = SSL_get_error(ssl, ret);
				if(x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
					break;
				else if(x == SSL_ERROR_ZERO_RETURN)
					v_eof = true;
				else
					return false;
			}
		}

		*plain = recvQueue.copy();
		recvQueue.resize(0);

		// could be outgoing data also
		*to_net = readOutgoing();
		return true;
	}

	QByteArray unprocessed()
	{
		QByteArray a;
		int size = BIO_pending(rbio);
		if(size <= 0)
			return a;
		a.resize(size);

		int r = BIO_read(rbio, a.data(), size);
		if(r <= 0) {
			a.resize(0);
			return a;
		}
		if(r != size)
			a.resize(r);
		return a;
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

	int doShutdown()
	{
		int ret = SSL_shutdown(ssl);
		if(ret >= 1)
			return Good;
		else {
			if(ret == 0)
				return TryAgain;
			int x = SSL_get_error(ssl, ret);
			if(x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
				return TryAgain;
			return Bad;
		}
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

	void init()
	{
	}

	int qcaVersion() const
	{
		return QCA_PLUGIN_VERSION;
	}

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
QCAProvider *createProviderTLS()
#endif
{
	return (new QCAOpenSSL);
}
