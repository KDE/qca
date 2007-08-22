DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib
TARGET = tlsunittest

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = tlsunittest
test.commands = ./tlsunittest

# Input
SOURCES += tlsunittest.cpp
