#ifndef QCAPROVIDER_H
#define QCAPROVIDER_H

#include"qca.h"

class QCAProvider
{
public:
	QCAProvider() {}
	virtual ~QCAProvider() {}

	virtual int capabilities() const=0;

	// sha1
	virtual int sha1_create()=0;
	virtual void sha1_destroy(int ctx)=0;
	virtual void sha1_update(int ctx, const char *in, unsigned int len)=0;
	virtual void sha1_final(int ctx, char *out)=0; // 20 bytes output
};

#endif
