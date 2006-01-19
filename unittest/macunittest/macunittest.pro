TEMPLATE = app
TARGET = macunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = macunittest
check.commands = ./macunittest

# Input
HEADERS += macunittest.h
SOURCES += macunittest.cpp
