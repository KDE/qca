TEMPLATE = app
TARGET = filewatchunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = filewatchunittest
check.commands = ./filewatchunittest

# Input
HEADERS += filewatchunittest.h
SOURCES += filewatchunittest.cpp
