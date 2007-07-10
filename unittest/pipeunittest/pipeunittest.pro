DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = pipeunittest
test.commands = ./pipeunittest

# Input
SOURCES += pipeunittest.cpp
