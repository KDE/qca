DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = macunittest
check.commands = ./macunittest

# Input
SOURCES += macunittest.cpp
