TEMPLATE = app
TARGET = kdfunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = kdfunittest
check.commands = ./kdfunittest

# Input
SOURCES += kdfunittest.cpp
