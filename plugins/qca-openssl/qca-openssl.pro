TEMPLATE = lib
CONFIG  += qt thread debug plugin
#CONFIG  += qt thread release plugin
TARGET   = qca-openssl

DEFINES += QCA_PLUGIN

INCLUDEPATH += ../../include
SOURCES = qca-openssl.cpp

#temp hack until build system is fixed.
DEFINES += OSSL_097
LIBS += -lssl -lcrypto

#include(conf.pri)
#include(extra.pri)
