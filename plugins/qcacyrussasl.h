#ifndef QCACYRUSSASL_H
#define QCACYRUSSASL_H

#include"qcaprovider.h"

#ifdef QCA_PLUGIN
QCA_EXPORT QCAProvider *createProvider();
#else
QCAProvider *createProviderCyrusSASL();
#endif

#endif
