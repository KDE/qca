TEMPLATE = app
TARGET = securearrayunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = securearrayunittest
check.commands = ./securearrayunittest

# Input
SOURCES += securearrayunittest.cpp
