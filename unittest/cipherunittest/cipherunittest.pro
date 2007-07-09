DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = cipherunittest
test.commands = ./cipherunittest

# Input
SOURCES += cipherunittest.cpp
