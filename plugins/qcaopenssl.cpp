#include"qcaopenssl_p.h"

#include<qptrlist.h>
#include<openssl/sha.h>

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

struct pair_sha1
{
	int ctx;
	SHA_CTX c;
};

typedef QPtrList<pair_sha1> map_sha1;
map_sha1 *map = 0;

static pair_sha1 *find(int ctx)
{
	QPtrListIterator<pair_sha1> it(*map);
	for(pair_sha1 *p; (p = it.current()); ++it) {
		if(p->ctx == ctx)
			return p;
	}
	return 0;
}

_QCAOpenSSL::_QCAOpenSSL()
{
	map = new map_sha1;
	map->setAutoDelete(true);
}

_QCAOpenSSL::~_QCAOpenSSL()
{
	delete map;
	map = 0;
}

int _QCAOpenSSL::capabilities() const
{
	return QCA::CAP_SHA1;
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
	return 0;
}

int sha1_create()
{
	pair_sha1 *i = new pair_sha1;
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
