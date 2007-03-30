TEMPLATE = app
TARGET = keylengthunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = keylengthunittest
check.commands = ./keylengthunittest

# Input
SOURCES += keylengthunittest.cpp
