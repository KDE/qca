# QCAOpenSSL qmake profile

TEMPLATE = lib
CONFIG  += qt thread release plugin
TARGET   = qcaopenssl

INCLUDEPATH += ../src

# RH 9
INCLUDEPATH += /usr/kerberos/include

HEADERS = ../src/qcaprovider.h qcaopenssl.h
SOURCES = qcaopenssl.cpp
DEFINES += QCA_PLUGIN

# link with OpenSSL
LIBS += -lcrypto -lssl

