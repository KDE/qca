DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = rsaunittest
test.commands = ./rsaunittest

# Input
SOURCES += rsaunittest.cpp
