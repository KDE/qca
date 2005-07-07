TEMPLATE = lib
CONFIG += plugin
QT -= gui

#CONFIG += release
CONFIG += debug

QCA_INC = ../../include/QtCrypto
QCA_LIB = ../..

INCLUDEPATH += $$QCA_INC
LIBS += -L$$QCA_LIB -lqca

SOURCES = qca-openssl.cpp

# temp hack
DEFINES += OSSL_097
unix:LIBS += -lssl -lcrypto
windows:{
	INCLUDEPATH += /local/include
	LIBS += -L/local/lib -llibeay32 -lssleay32
	LIBS += -lgdi32 -lwsock32
}

#include(conf.pri)
#include(extra.pri)
