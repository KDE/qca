DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = staticunittest
test.commands = ./staticunittest

# Input
SOURCES += staticunittest.cpp
