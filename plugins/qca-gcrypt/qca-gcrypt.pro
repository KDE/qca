TEMPLATE = lib
CONFIG  += qt thread debug plugin
#CONFIG  += qt thread release plugin
QT -= gui
TARGET   = qca-gcrypt

DEFINES += QCA_PLUGIN

INCLUDEPATH += ../../include/QtCrypto
SOURCES = qca-gcrypt.cpp

include(conf.pri)

# install
target.path += $$[QT_INSTALL_PLUGINS]/crypto
INSTALLS += target

