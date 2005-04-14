QT -= gui
CONFIG += console
CONFIG -= app_bundle

INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../.. -lqca

SOURCES += main.cpp

