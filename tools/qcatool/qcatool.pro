QT -= gui
CONFIG += console
CONFIG -= app_bundle
DESTDIR = ../../bin

INCLUDEPATH += ../../include/QtCrypto
SOURCES = main.cpp

LIBS += -L../.. -lqca

include(../../conf.pri)

target.path=$$BINDIR
INSTALLS += target

# temporarily build directly against openssl
DEFINES += QT_STATICPLUGIN
SOURCES += ../../plugins/qca-openssl/qca-openssl.cpp
DEFINES += OSSL_097
LIBS += -lcrypto

