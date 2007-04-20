DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = kdfunittest
check.commands = ./kdfunittest

# Input
SOURCES += kdfunittest.cpp
