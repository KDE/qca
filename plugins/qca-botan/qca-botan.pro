TEMPLATE = lib
CONFIG  += qt thread debug plugin
#CONFIG  += qt thread release plugin
QT -= gui
TARGET   = qca-botan

DEFINES += QCA_PLUGIN

INCLUDEPATH += ../../include/QtCrypto
SOURCES = qca-botan.cpp

include(conf.pri)

target.path += $$[QT_INSTALL_PLUGINS]/crypto
INSTALLS += target

