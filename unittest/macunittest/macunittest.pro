DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = macunittest
test.commands = ./macunittest

# Input
SOURCES += macunittest.cpp
