TEMPLATE = lib
CONFIG  += qt thread debug plugin
QT -= gui
TARGET   = qca-cyrus-sasl

DEFINES += QCA_PLUGIN

INCLUDEPATH += ../../include/QtCrypto
SOURCES = qca-cyrus-sasl.cpp

# a temporary hack until the build system works
LIBS += -lsasl2
