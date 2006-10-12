TEMPLATE = app
TARGET = certunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = certunittest
check.commands = ./certunittest

# Input
SOURCES += certunittest.cpp
