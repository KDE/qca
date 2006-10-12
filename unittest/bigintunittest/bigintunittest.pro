TEMPLATE = app
TARGET = bigintunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = bigintunittest
check.commands = ./bigintunittest

# Input
SOURCES += bigintunittest.cpp
