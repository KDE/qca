# QCAOpenSSL qmake profile

TEMPLATE = lib
CONFIG  += qt thread release plugin
TARGET   = qcaopenssl

INCLUDEPATH += ../src

# RH 9
INCLUDEPATH += /usr/kerberos/include

HEADERS = qcaopenssl.h qcaopenssl_p.h
SOURCES = qcaopenssl.cpp
DEFINES += QCA_PLUGIN

# link with OpenSSL
LIBS += -L/usr/local/lib -lcrypto

