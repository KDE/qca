TEMPLATE = lib
CONFIG  += qt thread debug plugin
#CONFIG  += qt thread release plugin
TARGET   = qca-gcrypt

!exists(qcaprovider.h) {
  Q_PREFIX = ../../src
  INCLUDEPATH += $$Q_PREFIX
}

DEFINES += QCA_PLUGIN

INCLUDEPATH += ../src
SOURCES = qca-gcrypt.cpp
LIBS += -lgcrypt -lgpg-error

#include(conf.pri)
#include(extra.pri)
