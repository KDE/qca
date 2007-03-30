TEMPLATE = app
TARGET = hashunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = hashunittest
check.commands = ./hashunittest

# Input
SOURCES += hashunittest.cpp
