TEMPLATE = app
TARGET = randomunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = randomunittest
check.commands = ./randomunittest

# Input
SOURCES += randomunittest.cpp
