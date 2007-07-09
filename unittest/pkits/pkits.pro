DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = pkits
test.commands = ./pkits

# Input
SOURCES += pkits.cpp
