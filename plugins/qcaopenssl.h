#ifndef QCAOPENSSL_H
#define QCAOPENSSL_H

#include"qcaprovider.h"

#ifdef QCA_PLUGIN
QCA_EXPORT QCAProvider *createProvider();
#else
QCAProvider *createProviderOpenSSL();
#endif

#endif
