DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = hashunittest
check.commands = ./hashunittest

# Input
SOURCES += hashunittest.cpp
