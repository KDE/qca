# QCACyrusSASL qmake profile

TEMPLATE = lib
CONFIG  += qt thread release plugin
TARGET   = qcacyrussasl

INCLUDEPATH += ../src

HEADERS = ../src/qcaprovider.h qcacyrussasl.h
SOURCES = qcacyrussasl.cpp
DEFINES += QCA_PLUGIN

# link with Cyrus SASL
LIBS += -lsasl2

