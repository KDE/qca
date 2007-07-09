DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = keybundle
test.commands = ./keybundle

# Input
SOURCES += keybundle.cpp
