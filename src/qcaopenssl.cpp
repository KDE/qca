#include"qcaopenssl.h"

#include<openssl/sha.h>

class QCAOpenSSL::Private
{
public:
	SHA_CTX *c;
};

QCAOpenSSL::QCAOpenSSL()
{
	d = new Private;
	d->c = 0;
}

QCAOpenSSL::~QCAOpenSSL()
{
	delete d;
}

int QCAOpenSSL::capabilities() const
{
	return QCA::CAP_SHA1;
}

int QCAOpenSSL::sha1_create()
{
	d->c = new SHA_CTX;
	SHA1_Init(d->c);
	return 0;
}

void QCAOpenSSL::sha1_destroy(int ctx)
{
	delete d->c;
}

void QCAOpenSSL::sha1_update(int ctx, const char *in, unsigned int len)
{
	SHA1_Update(d->c, in, len);
}

void QCAOpenSSL::sha1_final(int ctx, char *out)
{
	SHA1_Final((unsigned char *)out, d->c);
}
