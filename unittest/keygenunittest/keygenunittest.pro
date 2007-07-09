DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = keygenunittest
test.commands = ./keygenunittest

# Input
SOURCES += keygenunittest.cpp
