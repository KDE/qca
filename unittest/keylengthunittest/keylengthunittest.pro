TEMPLATE = app
TARGET = keylengthunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = keylengthunittest
check.commands = ./keylengthunittest

# Input
HEADERS += keylengthunittest.h
SOURCES += keylengthunittest.cpp
