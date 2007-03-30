TEMPLATE = app
TARGET = certunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = certunittest
check.commands = ./certunittest

# Input
SOURCES += certunittest.cpp
