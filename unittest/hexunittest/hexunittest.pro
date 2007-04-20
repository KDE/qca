DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = hexunittest
check.commands = ./hexunittest

# Input
SOURCES += hexunittest.cpp
