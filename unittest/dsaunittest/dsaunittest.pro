DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = dsaunittest
test.commands = ./dsaunittest

# Input
SOURCES += dsaunittest.cpp
