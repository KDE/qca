#ifndef QCAOPENSSL_H
#define QCAOPENSSL_H

#include"qcaprovider.h"

class QCAOpenSSL : public QCAProvider
{
public:
	QCAOpenSSL();
	~QCAOpenSSL();

	int capabilities() const;

	int sha1_create();
	void sha1_destroy(int ctx);
	void sha1_update(int ctx, const char *in, unsigned int len);
	void sha1_final(int ctx, char *out);

private:
	class Private;
	Private *d;
};

#endif
