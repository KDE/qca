# qca-tls qmake profile

TEMPLATE = lib
CONFIG  += qt thread release plugin
TARGET   = qca-tls

!exists(qcaprovider.h) {
  Q_PREFIX = ../../src
  INCLUDEPATH += $$Q_PREFIX
}
HEADERS += ($$Q_PREFIX)qcaprovider.h

HEADERS = qca-tls.h
SOURCES = qca-tls.cpp

DEFINES += QCA_PLUGIN
win32:{
	DEFINES += QCA_PLUGIN_DLL OSS_097
	INCLUDEPATH += c:\local\include
	LIBS += c:\local\lib\libeay32.lib c:\local\lib\ssleay32.lib
}

include(conf.pri)
include(extra.pri)

