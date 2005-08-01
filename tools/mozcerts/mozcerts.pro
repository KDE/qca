QT -= gui
CONFIG += console
CONFIG -= app_bundle

INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca

SOURCES += main.cpp

