TEMPLATE = app
TARGET = staticunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = staticunittest
check.commands = ./staticunittest

# Input
SOURCES += staticunittest.cpp
