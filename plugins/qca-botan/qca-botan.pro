TEMPLATE = lib
CONFIG  += qt thread debug plugin
#CONFIG  += qt thread release plugin
TARGET   = qca-botan

!exists(qcaprovider.h) {
  Q_PREFIX = ../../src
  INCLUDEPATH += $$Q_PREFIX
}

DEFINES += QCA_PLUGIN

INCLUDEPATH += ../src
SOURCES = qca-botan.cpp
LIBS += -L/usr/local/lib -lm -lpthread -lrt -lbotan

#include(conf.pri)
#include(extra.pri)
