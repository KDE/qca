DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = hashunittest
test.commands = ./hashunittest

# Input
SOURCES += hashunittest.cpp
