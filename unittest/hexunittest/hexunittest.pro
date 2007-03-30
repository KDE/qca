TEMPLATE = app
TARGET = hexunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = hexunittest
check.commands = ./hexunittest

# Input
SOURCES += hexunittest.cpp
