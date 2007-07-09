DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = securearrayunittest
test.commands = ./securearrayunittest

# Input
SOURCES += securearrayunittest.cpp
