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

struct QCA_HashFunctions
{
	int (*create)();
	void (*destroy)(int ctx);
	void (*update)(int ctx, const char *in, unsigned int len);
	void (*final)(int ctx, char *out);
	unsigned int (*finalSize)(int ctx);
};

struct QCA_CipherFunctions
{
	int (*keySize)();
	int (*blockSize)();
	bool (*generateKey)(char *out);
	bool (*generateIV)(char *out);

	int (*create)();
	void (*destroy)(int ctx);
	bool (*setup)(int ctx, int dir, const char *key, const char *iv);
	bool (*update)(int ctx, const char *in, unsigned int len);
	bool (*final)(int ctx, char *out);
	unsigned int (*finalSize)(int ctx);
};

struct QCA_RSAFunctions
{
	int (*keyCreateFromDER)(const char *in, unsigned int len, bool sec);
	int (*keyCreateGenerate)(unsigned int bits);
	int (*keyClone)(int ctx);
	void (*keyDestroy)(int ctx);
	void (*keyToDER)(int ctx, char **out, unsigned int *len);

	bool (*encrypt)(int ctx, const char *in, unsigned int len, char **out, unsigned int *outlen);
	bool (*decrypt)(int ctx, const char *in, unsigned int len, char **out, unsigned int *outlen);
};

#endif
