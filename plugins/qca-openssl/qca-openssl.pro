TEMPLATE = lib
CONFIG  += qt thread debug plugin
#CONFIG  += qt thread release plugin
TARGET   = qca-openssl

!exists(qcaprovider.h) {
  Q_PREFIX = ../../src
  INCLUDEPATH += $$Q_PREFIX
}

DEFINES += QCA_PLUGIN

INCLUDEPATH += ../src
SOURCES = qca-openssl.cpp
LIBS += -L .. -lqca -lcrypto

include(conf.pri)
include(extra.pri)
