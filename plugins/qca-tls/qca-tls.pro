# qca-tls qmake profile

TEMPLATE = lib
CONFIG  += qt thread release plugin
TARGET   = qca-tls

!exists(qcaprovider.h) {
  Q_PREFIX = ../../src
  INCLUDEPATH += $$Q_PREFIX/
}
HEADERS += ($$Q_PREFIX)qcaprovider.h

HEADERS = qca-tls.h
SOURCES = qca-tls.cpp
DEFINES += QCA_PLUGIN

include(conf.pri)
include(extra.pri)

