TEMPLATE = app
TARGET = randomunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = randomunittest
check.commands = ./randomunittest

# Input
SOURCES += randomunittest.cpp
