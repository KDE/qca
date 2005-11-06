TEMPLATE = app
TARGET = kdfunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qttest thread console

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = kdfunittest
check.commands = ./kdfunittest

# Input
HEADERS += kdfunittest.h
SOURCES += kdfunittest.cpp
