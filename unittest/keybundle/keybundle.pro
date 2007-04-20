DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = keybundle
check.commands = ./keybundle

# Input
SOURCES += keybundle.cpp
