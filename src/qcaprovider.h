#ifndef QCAPROVIDER_H
#define QCAPROVIDER_H

#include"qca.h"

class QCAProvider
{
public:
	QCAProvider() {}
	virtual ~QCAProvider() {}

	virtual int capabilities() const=0;
	virtual void *functions(int cap)=0;
};

struct QCA_SHA1Functions
{
	int (*create)();
	void (*destroy)(int ctx);
	void (*update)(int ctx, const char *in, unsigned int len);
	void (*final)(int ctx, char *out); // 20 bytes output
};

#endif
