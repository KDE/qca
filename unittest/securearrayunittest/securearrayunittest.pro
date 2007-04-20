DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = securearrayunittest
check.commands = ./securearrayunittest

# Input
SOURCES += securearrayunittest.cpp
