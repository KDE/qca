TEMPLATE = lib
CONFIG  += qt thread debug plugin
#CONFIG  += qt thread release plugin
QT -= gui
TARGET   = qca-gcrypt

DEFINES += QCA_PLUGIN

INCLUDEPATH += ../../include/QtCrypto
SOURCES = qca-gcrypt.cpp

# temp hack until the build system works again
LIBS +=  -lgcrypt -lgpg-error

#include(conf.pri)
#include(extra.pri)
