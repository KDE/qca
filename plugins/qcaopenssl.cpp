#include"qcaopenssl_p.h"

#include<qptrlist.h>
#include<openssl/sha.h>
#include<openssl/md5.h>
#include<openssl/evp.h>

#ifdef QCA_PLUGIN
QCAProvider *createProvider()
{
	return (new _QCAOpenSSL);
}
#endif

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

static int tdes_create();
static void tdes_destroy(int ctx);
static void tdes_setup(int ctx, int dir, const char *key, const char *iv);
static void tdes_update(int ctx, const char *in, unsigned int len);
static void tdes_final(int ctx, char *out);
static unsigned int tdes_finalSize(int ctx);

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
};
typedef QPtrList<pair_tdes> MAP_TDES;
MAP_TDES *map_tdes = 0;

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

_QCAOpenSSL::_QCAOpenSSL()
{
	map = new MAP_SHA1;
	map->setAutoDelete(true);
	map_md5 = new MAP_MD5;
	map_md5->setAutoDelete(true);
	map_tdes = new MAP_TDES;
	map_tdes->setAutoDelete(true);
}

_QCAOpenSSL::~_QCAOpenSSL()
{
	delete map;
	map = 0;
	delete map_md5;
	map_md5 = 0;
	delete map_tdes;
	map_tdes = 0;
}

int _QCAOpenSSL::capabilities() const
{
	return (QCA::CAP_SHA1 | QCA::CAP_MD5 | QCA::CAP_TripleDES);
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
		f->create = tdes_create;
		f->destroy = tdes_destroy;
		f->setup = tdes_setup;
		f->update = tdes_update;
		f->final = tdes_final;
		f->finalSize = tdes_finalSize;
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

int tdes_create()
{
	pair_tdes *i = new pair_tdes;
	i->ctx = counter++;
	i->type = EVP_des_ede3_cbc();
	i->dir = 0;
	i->done = false;
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

void tdes_setup(int ctx, int dir, const char *key, const char *iv)
{
	pair_tdes *i = find_tdes(ctx);
	i->dir = dir;

	if(i->dir == 0)
		EVP_EncryptInit_ex(&i->c, i->type, NULL, (const unsigned char *)key, (const unsigned char *)iv);
	else
		EVP_DecryptInit_ex(&i->c, i->type, NULL, (const unsigned char *)key, (const unsigned char *)iv);
}

void tdes_update(int ctx, const char *in, unsigned int len)
{
	pair_tdes *i = find_tdes(ctx);

	i->done = false;
	QByteArray result(len + i->type->block_size);
	int olen;
	if(i->dir == 0)
		EVP_EncryptUpdate(&i->c, (unsigned char *)result.data(), &olen, (const unsigned char *)in, len);
	else
		EVP_DecryptUpdate(&i->c, (unsigned char *)result.data(), &olen, (const unsigned char *)in, len);
	result.resize(olen);
	appendArray(&i->r, result);
}

static void tdes_ensureFinal(pair_tdes *i)
{
	if(i->done)
		return;

	QByteArray result(i->type->block_size);
	int olen;
	if(i->dir == 0)
		EVP_EncryptFinal(&i->c, (unsigned char *)result.data(), &olen);
	else
		EVP_DecryptFinal(&i->c, (unsigned char *)result.data(), &olen);
	result.resize(olen);
	appendArray(&i->r, result);
	i->done = true;
}

void tdes_final(int ctx, char *out)
{
	pair_tdes *i = find_tdes(ctx);
	tdes_ensureFinal(i);
	memcpy(out, i->r.data(), i->r.size());
}

unsigned int tdes_finalSize(int ctx)
{
	pair_tdes *i = find_tdes(ctx);
	tdes_ensureFinal(i);
	return i->r.size();
}

