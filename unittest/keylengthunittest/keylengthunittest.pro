DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = keylengthunittest
check.commands = ./keylengthunittest

# Input
SOURCES += keylengthunittest.cpp
