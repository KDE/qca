DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = staticunittest
check.commands = ./staticunittest

# Input
SOURCES += staticunittest.cpp
