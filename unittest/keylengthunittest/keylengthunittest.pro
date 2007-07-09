DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = keylengthunittest
test.commands = ./keylengthunittest

# Input
SOURCES += keylengthunittest.cpp
