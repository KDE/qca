DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = randomunittest
test.commands = ./randomunittest

# Input
SOURCES += randomunittest.cpp
