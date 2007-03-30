QT -= gui
CONFIG += console
CONFIG -= app_bundle
include(../../confapp.pri)

INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -l$$QCA_LIBNAME

SOURCES += main.cpp
