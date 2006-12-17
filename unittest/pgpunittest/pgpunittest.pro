TEMPLATE = app
TARGET = pgpunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = pgpunittest
check.commands = ./pgpunittest

# Input
SOURCES += pgpunittest.cpp
