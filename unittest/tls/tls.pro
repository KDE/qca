DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = tlsunittest
test.commands = ./tlsunittest

# Input
SOURCES += tlsunittest.cpp
