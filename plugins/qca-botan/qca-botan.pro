TEMPLATE = lib
CONFIG  += qt thread debug plugin
#CONFIG  += qt thread release plugin
QT -= gui
TARGET   = qca-botan

DEFINES += QCA_PLUGIN

INCLUDEPATH += ../../include/QtCrypto
SOURCES = qca-botan.cpp

#temp hack until build system is fixed
#include(conf.pri)
#include(extra.pri)
LIBS += -L/usr/lib -lm -lpthread -lrt -lbotan
