DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = kdfunittest
test.commands = ./kdfunittest

# Input
SOURCES += kdfunittest.cpp
