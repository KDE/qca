TEMPLATE = lib
CONFIG  += qt thread debug plugin
#CONFIG  += qt thread release plugin
TARGET   = qca-openssl

DEFINES += QCA_PLUGIN

INCLUDEPATH += ../../include
SOURCES = qca-openssl.cpp

include(conf.pri)
include(extra.pri)
