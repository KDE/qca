#include"qcaopenssl_p.h"

#include<qptrlist.h>
#include<openssl/sha.h>
#include<openssl/md5.h>

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

static int md5_create();
static void md5_destroy(int ctx);
static void md5_update(int ctx, const char *in, unsigned int len);
static void md5_final(int ctx, char *out);

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

_QCAOpenSSL::_QCAOpenSSL()
{
	map = new MAP_SHA1;
	map->setAutoDelete(true);
	map_md5 = new MAP_MD5;
	map_md5->setAutoDelete(true);
}

_QCAOpenSSL::~_QCAOpenSSL()
{
	delete map;
	map = 0;
	delete map_md5;
	map_md5 = 0;
}

int _QCAOpenSSL::capabilities() const
{
	return (QCA::CAP_SHA1 | QCA::CAP_MD5);
}

void *_QCAOpenSSL::functions(int cap)
{
	if(cap == QCA::CAP_SHA1) {
		QCA_SHA1Functions *f = new QCA_SHA1Functions;
		f->create = sha1_create;
		f->destroy = sha1_destroy;
		f->update = sha1_update;
		f->final = sha1_final;
		return f;
	}
	else if(cap == QCA::CAP_MD5) {
		QCA_MD5Functions *f = new QCA_MD5Functions;
		f->create = md5_create;
		f->destroy = md5_destroy;
		f->update = md5_update;
		f->final = md5_final;
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

