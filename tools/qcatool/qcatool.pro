QT -= gui

INCLUDEPATH += ../../include/QtCrypto
SOURCES = main.cpp

LIBS += -L../.. -lqca

# temporarily build directly against openssl
DEFINES += QT_STATICPLUGIN
SOURCES += ../../plugins/qca-openssl/qca-openssl.cpp
DEFINES += OSSL_097
LIBS += -lcrypto

