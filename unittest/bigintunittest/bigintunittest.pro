TEMPLATE = app
TARGET = bigintunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qttest thread console
# check target

QMAKE_EXTRA_TARGETS = check
check.depends = bigintunittest
check.commands = ./bigintunittest

# Input
HEADERS += bigintunittest.h
SOURCES += bigintunittest.cpp
