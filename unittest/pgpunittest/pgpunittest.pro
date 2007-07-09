DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = pgpunittest
test.commands = ./pgpunittest

# Input
SOURCES += pgpunittest.cpp
