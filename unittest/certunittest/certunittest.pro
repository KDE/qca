DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = certunittest
test.commands = ./certunittest

# Input
SOURCES += certunittest.cpp
