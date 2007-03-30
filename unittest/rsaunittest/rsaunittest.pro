TEMPLATE = app
TARGET = rsaunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = rsaunittest
check.commands = ./rsaunittest

# Input
HEADERS += rsaunittest.h
SOURCES += rsaunittest.cpp
