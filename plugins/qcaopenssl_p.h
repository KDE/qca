#ifndef QCAOPENSSL_P_H
#define QCAOPENSSL_P_H

#include"qcaopenssl.h"

class _QCAOpenSSL : public QCAOpenSSL
{
public:
	_QCAOpenSSL();
	~_QCAOpenSSL();

	int capabilities() const;
	void *functions(int cap);
};

#endif
