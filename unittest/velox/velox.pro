TEMPLATE = app
TARGET = veloxunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui
QT += network

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = veloxunittest
check.commands = ./veloxunittest

# Input
SOURCES += veloxunittest.cpp
