QT -= gui
CONFIG += console
CONFIG -= app_bundle
include(../../confapp.pri)

INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca

SOURCES += main.cpp

