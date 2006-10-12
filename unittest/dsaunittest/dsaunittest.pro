TEMPLATE = app
TARGET = dsaunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = dsaunittest
check.commands = ./dsaunittest

# Input
SOURCES += dsaunittest.cpp
