# qca-sasl qmake profile

TEMPLATE = lib
CONFIG  += qt thread release plugin
TARGET   = qca-sasl

!exists(qcaprovider.h) {
  Q_PREFIX = ../../src
  INCLUDEPATH += $$Q_PREFIX
}
HEADERS += ($$Q_PREFIX)qcaprovider.h

HEADERS = qca-sasl.h
SOURCES = qca-sasl.cpp
DEFINES += QCA_PLUGIN

include(conf.pri)
include(extra.pri)
