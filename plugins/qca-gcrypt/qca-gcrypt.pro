TEMPLATE = lib
CONFIG  += qt thread debug plugin
#CONFIG  += qt thread release plugin
TARGET   = qca-gcrypt

DEFINES += QCA_PLUGIN

INCLUDEPATH += ../../include
SOURCES = qca-gcrypt.cpp

include(conf.pri)
include(extra.pri)
