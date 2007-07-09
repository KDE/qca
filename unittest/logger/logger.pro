DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = loggerunittest
test.commands = ./loggerunittest

# Input
SOURCES += loggerunittest.cpp
