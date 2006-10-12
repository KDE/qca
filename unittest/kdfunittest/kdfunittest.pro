TEMPLATE = app
TARGET = kdfunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = kdfunittest
check.commands = ./kdfunittest

# Input
SOURCES += kdfunittest.cpp
