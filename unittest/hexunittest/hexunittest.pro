DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = hexunittest
test.commands = ./hexunittest

# Input
SOURCES += hexunittest.cpp
