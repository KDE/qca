#include"qcaopenssl_p.h"

#include<qptrlist.h>
#include<openssl/sha.h>
#include<openssl/md5.h>
#include<openssl/evp.h>
#include<openssl/rsa.h>
#include<openssl/x509.h>

#ifdef QCA_PLUGIN
QCAProvider *createProvider()
{
	return (new _QCAOpenSSL);
}
#endif

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

static int sha1_create();
static void sha1_destroy(int ctx);
static void sha1_update(int ctx, const char *in, unsigned int len);
static void sha1_final(int ctx, char *out);
static unsigned int sha1_finalSize(int ctx);

static int md5_create();
static void md5_destroy(int ctx);
static void md5_update(int ctx, const char *in, unsigned int len);
static void md5_final(int ctx, char *out);
static unsigned int md5_finalSize(int ctx);

static int tdes_keySize() { return 24; }
static int tdes_blockSize() { return 8; }
static bool tdes_generateKey(char *out);
static bool tdes_generateIV(char *out);

static int tdes_create();
static void tdes_destroy(int ctx);
static bool tdes_setup(int ctx, int dir, const char *key, const char *iv);
static bool tdes_update(int ctx, const char *in, unsigned int len);
static bool tdes_final(int ctx, char *out);
static unsigned int tdes_finalSize(int ctx);

static int rsa_keyCreateFromDER(const char *in, unsigned int len, bool sec);
static int rsa_keyCreateGenerate(unsigned int bits);
static int rsa_keyClone(int ctx);
static void rsa_keyDestroy(int ctx);
static void rsa_keyToDER(int ctx, char **out, unsigned int *len);
static bool rsa_encrypt(int ctx, const char *in, unsigned int len, char **out, unsigned int *outlen);
static bool rsa_decrypt(int ctx, const char *in, unsigned int len, char **out, unsigned int *outlen);

static void appendArray(QByteArray *a, const QByteArray &b)
{
	int oldsize = a->size();
	a->resize(oldsize + b.size());
	memcpy(a->data() + oldsize, b.data(), b.size());
}

static int counter = 0;

struct pair_sha1
{
	int ctx;
	SHA_CTX c;
};
typedef QPtrList<pair_sha1> MAP_SHA1;
MAP_SHA1 *map = 0;

struct pair_md5
{
	int ctx;
	MD5_CTX c;
};
typedef QPtrList<pair_md5> MAP_MD5;
MAP_MD5 *map_md5 = 0;

struct pair_tdes
{
	int ctx;
	EVP_CIPHER_CTX c;
	const EVP_CIPHER *type;
	QByteArray r;
	int dir;
	bool done;
	bool err;
};
typedef QPtrList<pair_tdes> MAP_TDES;
MAP_TDES *map_tdes = 0;

struct pair_rsakey
{
	int ctx;
	RSA *r;
};
typedef QPtrList<pair_rsakey> MAP_RSAKEY;
MAP_RSAKEY *map_rsakey = 0;

static pair_sha1 *find(int ctx)
{
	QPtrListIterator<pair_sha1> it(*map);
	for(pair_sha1 *p; (p = it.current()); ++it) {
		if(p->ctx == ctx)
			return p;
	}
	return 0;
}

static pair_md5 *find_md5(int ctx)
{
	QPtrListIterator<pair_md5> it(*map_md5);
	for(pair_md5 *p; (p = it.current()); ++it) {
		if(p->ctx == ctx)
			return p;
	}
	return 0;
}

static pair_tdes *find_tdes(int ctx)
{
	QPtrListIterator<pair_tdes> it(*map_tdes);
	for(pair_tdes *p; (p = it.current()); ++it) {
		if(p->ctx == ctx)
			return p;
	}
	return 0;
}

static pair_rsakey *find_rsakey(int ctx)
{
	QPtrListIterator<pair_rsakey> it(*map_rsakey);
	for(pair_rsakey *p; (p = it.current()); ++it) {
		if(p->ctx == ctx)
			return p;
	}
	return 0;
}

_QCAOpenSSL::_QCAOpenSSL()
{
	map = new MAP_SHA1;
	map->setAutoDelete(true);
	map_md5 = new MAP_MD5;
	map_md5->setAutoDelete(true);
	map_tdes = new MAP_TDES;
	map_tdes->setAutoDelete(true);
	map_rsakey = new MAP_RSAKEY;
	map_rsakey->setAutoDelete(true);
}

_QCAOpenSSL::~_QCAOpenSSL()
{
	delete map;
	map = 0;
	delete map_md5;
	map_md5 = 0;
	delete map_tdes;
	map_tdes = 0;
	delete map_rsakey;
	map_rsakey = 0;
}

int _QCAOpenSSL::capabilities() const
{
	return (QCA::CAP_SHA1 | QCA::CAP_MD5 | QCA::CAP_TripleDES | QCA::CAP_RSA);
}

void *_QCAOpenSSL::functions(int cap)
{
	if(cap == QCA::CAP_SHA1) {
		QCA_HashFunctions *f = new QCA_HashFunctions;
		f->create = sha1_create;
		f->destroy = sha1_destroy;
		f->update = sha1_update;
		f->final = sha1_final;
		f->finalSize = sha1_finalSize;
		return f;
	}
	else if(cap == QCA::CAP_MD5) {
		QCA_HashFunctions *f = new QCA_HashFunctions;
		f->create = md5_create;
		f->destroy = md5_destroy;
		f->update = md5_update;
		f->final = md5_final;
		f->finalSize = md5_finalSize;
		return f;
	}
	else if(cap == QCA::CAP_TripleDES) {
		QCA_CipherFunctions *f = new QCA_CipherFunctions;
		f->keySize = tdes_keySize;
		f->blockSize = tdes_blockSize;
		f->generateKey = tdes_generateKey;
		f->generateIV = tdes_generateIV;
		f->create = tdes_create;
		f->destroy = tdes_destroy;
		f->setup = tdes_setup;
		f->update = tdes_update;
		f->final = tdes_final;
		f->finalSize = tdes_finalSize;
		return f;
	}
	else if(cap == QCA::CAP_RSA) {
		QCA_RSAFunctions *f = new QCA_RSAFunctions;
		f->keyCreateFromDER = rsa_keyCreateFromDER;
		f->keyCreateGenerate = rsa_keyCreateGenerate;
		f->keyClone = rsa_keyClone;
		f->keyDestroy = rsa_keyDestroy;
		f->keyToDER = rsa_keyToDER;
		f->encrypt = rsa_encrypt;
		f->decrypt = rsa_decrypt;
		return f;
	}

	return 0;
}

int sha1_create()
{
	pair_sha1 *i = new pair_sha1;
	i->ctx = counter++;
	SHA1_Init(&i->c);
	map->append(i);
	return i->ctx;
}

void sha1_destroy(int ctx)
{
	pair_sha1 *i = find(ctx);
	map->removeRef(i);
}

void sha1_update(int ctx, const char *in, unsigned int len)
{
	pair_sha1 *i = find(ctx);
	SHA1_Update(&i->c, in, len);
}

void sha1_final(int ctx, char *out)
{
	pair_sha1 *i = find(ctx);
	SHA1_Final((unsigned char *)out, &i->c);
}

unsigned int sha1_finalSize(int)
{
	return 20;
}

int md5_create()
{
	pair_md5 *i = new pair_md5;
	i->ctx = counter++;
	MD5_Init(&i->c);
	map_md5->append(i);
	return i->ctx;
}

void md5_destroy(int ctx)
{
	pair_md5 *i = find_md5(ctx);
	map_md5->removeRef(i);
}

void md5_update(int ctx, const char *in, unsigned int len)
{
	pair_md5 *i = find_md5(ctx);
	MD5_Update(&i->c, in, len);
}

void md5_final(int ctx, char *out)
{
	pair_md5 *i = find_md5(ctx);
	MD5_Final((unsigned char *)out, &i->c);
}

unsigned int md5_finalSize(int)
{
	return 16;
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

bool tdes_generateKey(char *out)
{
	const EVP_CIPHER *type = EVP_des_ede3_cbc();
	QByteArray a;
	if(!lib_generateKeyIV(type, QRandom::randomArray(128), QRandom::randomArray(2), &a, 0))
		return false;
	memcpy(out, a.data(), a.size());
	return true;
}

bool tdes_generateIV(char *out)
{
	const EVP_CIPHER *type = EVP_des_ede3_cbc();
	QByteArray a;
	if(!lib_generateKeyIV(type, QRandom::randomArray(128), QRandom::randomArray(2), 0, &a))
		return false;
	memcpy(out, a.data(), a.size());
	return true;
}

int tdes_create()
{
	pair_tdes *i = new pair_tdes;
	i->ctx = counter++;
	i->type = EVP_des_ede3_cbc();
	i->dir = 0;
	i->done = false;
	i->err = false;
	EVP_CIPHER_CTX_init(&i->c);
	map_tdes->append(i);
	return i->ctx;
}

void tdes_destroy(int ctx)
{
	pair_tdes *i = find_tdes(ctx);
	memset(&i->c, 0, sizeof(EVP_CIPHER_CTX));
	map_tdes->removeRef(i);
}

bool tdes_setup(int ctx, int dir, const char *key, const char *iv)
{
	pair_tdes *i = find_tdes(ctx);
	i->dir = dir;

	if(i->dir == 0) {
		if(!EVP_EncryptInit_ex(&i->c, i->type, NULL, (const unsigned char *)key, (const unsigned char *)iv)) {
			return false;
		}
	}
	else {
		if(!EVP_DecryptInit_ex(&i->c, i->type, NULL, (const unsigned char *)key, (const unsigned char *)iv)) {
			return false;
		}
	}
	return true;
}

bool tdes_update(int ctx, const char *in, unsigned int len)
{
	pair_tdes *i = find_tdes(ctx);

	i->done = false;
	i->err = false;
	QByteArray result(len + i->type->block_size);
	int olen;
	if(i->dir == 0) {
		if(!EVP_EncryptUpdate(&i->c, (unsigned char *)result.data(), &olen, (const unsigned char *)in, len))
			return false;
	}
	else {
		if(!EVP_DecryptUpdate(&i->c, (unsigned char *)result.data(), &olen, (const unsigned char *)in, len))
			return false;
	}
	result.resize(olen);
	appendArray(&i->r, result);
	return true;
}

static void tdes_ensureFinal(pair_tdes *i)
{
	if(i->done)
		return;

	QByteArray result(i->type->block_size);
	int olen;
	if(i->dir == 0) {
		if(!EVP_EncryptFinal(&i->c, (unsigned char *)result.data(), &olen)) {
			i->err = true;
			return;
		}
	}
	else {
		if(!EVP_DecryptFinal(&i->c, (unsigned char *)result.data(), &olen)) {
			i->err = true;
			return;
		}
	}
	result.resize(olen);
	appendArray(&i->r, result);
	i->done = true;
}

bool tdes_final(int ctx, char *out)
{
	pair_tdes *i = find_tdes(ctx);
	if(i->err)
		return false;

	tdes_ensureFinal(i);
	memcpy(out, i->r.data(), i->r.size());
	return true;
}

unsigned int tdes_finalSize(int ctx)
{
	pair_tdes *i = find_tdes(ctx);
	tdes_ensureFinal(i);
	return i->r.size();
}

int rsa_keyCreateFromDER(const char *in, unsigned int len, bool sec)
{
	RSA *r;
	if(sec) {
		const unsigned char *p = (const unsigned char *)in;
		r = d2i_RSAPrivateKey(NULL, &p, len);
	}
	else {
		unsigned char *p = (unsigned char *)in;
		r = d2i_RSA_PUBKEY(NULL, &p,len);
	}
	if(!r)
		return -1;

	pair_rsakey *i = new pair_rsakey;
	i->ctx = counter++;
	i->r = r;
	map_rsakey->append(i);
	//printf("created %d\n", i->ctx);
	return i->ctx;
}

int rsa_keyClone(int ctx)
{
	pair_rsakey *from = find_rsakey(ctx);
	pair_rsakey *i = new pair_rsakey;
	i->ctx = counter++;
	++from->r->references;
	i->r = from->r;
	map_rsakey->append(i);
	//printf("cloned %d to %d\n", from->ctx, i->ctx);
	return i->ctx;
}

void rsa_keyDestroy(int ctx)
{
	//printf("destroying %d\n", ctx);
	pair_rsakey *i = find_rsakey(ctx);
	RSA_free(i->r);
	map_rsakey->removeRef(i);
}

void rsa_keyToDER(int ctx, char **out, unsigned int *len)
{
	ctx = -1;
	*out = 0;
	*len = 0;
}

bool rsa_encrypt(int ctx, const char *in, unsigned int len, char **out, unsigned int *outlen)
{
	pair_rsakey *i = find_rsakey(ctx);

	//printf("using context %d [r=%p]\n", ctx, i->r);
	int size = RSA_size(i->r);
	int flen = len;
	if(flen >= size - 11)
		flen = size - 11;
	QByteArray result(size);
	unsigned char *from = (unsigned char *)in;
	unsigned char *to = (unsigned char *)result.data();
	int r = RSA_public_encrypt(flen, from, to, i->r, RSA_PKCS1_PADDING);
	if(r == -1)
		return false;
	result.resize(r);

	*out = (char *)malloc(result.size());
	memcpy((*out), result.data(), result.size());
	*outlen = result.size();
	return true;
}

bool rsa_decrypt(int ctx, const char *in, unsigned int len, char **out, unsigned int *outlen)
{
	pair_rsakey *i = find_rsakey(ctx);
	if(!i) {
		//printf("no key!!\n");
		return false;
	}
	//printf("using context %d [r=%p]\n", ctx, i->r);

	int size = RSA_size(i->r);
	int flen = len;
	QByteArray result(size);
	unsigned char *from = (unsigned char *)in;
	unsigned char *to = (unsigned char *)result.data();
	//printf("about to decrypt\n");
	int r = RSA_private_decrypt(flen, from, to, i->r, RSA_PKCS1_PADDING);
	//printf("done decrypt\n");
	if(r == -1)
		return false;
	result.resize(r);

	*out = (char *)malloc(result.size());
	memcpy((*out), result.data(), result.size());
	*outlen = result.size();
	return true;
}

int rsa_keyCreateGenerate(unsigned int bits)
{
	RSA *r = RSA_generate_key(bits, RSA_F4, NULL, NULL);
	if(!r)
		return -1;

	pair_rsakey *i = new pair_rsakey;
	i->ctx = counter++;
	i->r = r;
	map_rsakey->append(i);
	return i->ctx;
}
