TEMPLATE = lib
CONFIG  += qt thread debug plugin
#CONFIG  += qt thread release plugin
TARGET   = qca-botan

DEFINES += QCA_PLUGIN

INCLUDEPATH += ../../include
SOURCES = qca-botan.cpp

include(conf.pri)
include(extra.pri)
