TEMPLATE = app
TARGET = hashunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
# check target

QMAKE_EXTRA_TARGETS = check
check.depends = hashunittest
check.commands = ./hashunittest

# Input
HEADERS += hashunittest.h
SOURCES += hashunittest.cpp
