#ifndef QCAPROVIDER_H
#define QCAPROVIDER_H

#include<qglobal.h>
#include"qca.h"

#ifdef Q_WS_WIN
#define QCA_EXPORT extern "C" __declspec(dllexport)
#else
#define QCA_EXPORT extern "C"
#endif

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

struct QCA_MD5Functions
{
	int (*create)();
	void (*destroy)(int ctx);
	void (*update)(int ctx, const char *in, unsigned int len);
	void (*final)(int ctx, char *out); // 16 bytes output
};

#endif
