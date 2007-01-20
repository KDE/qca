TEMPLATE = app
TARGET = loggerunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = loggerunittest
check.commands = ./loggerunittest

# Input
SOURCES += loggerunittest.cpp
