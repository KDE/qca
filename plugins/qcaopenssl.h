#ifndef QCAOPENSSL_H
#define QCAOPENSSL_H

#include"qcaprovider.h"

#ifdef QCA_PLUGIN
QCA_EXPORT QCAProvider *createProvider();
#endif

class QCAOpenSSL : public QCAProvider
{
public:
	QCAOpenSSL() {}
};

#endif
