TEMPLATE = app
TARGET = staticunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = staticunittest
check.commands = ./staticunittest

# Input
SOURCES += staticunittest.cpp
