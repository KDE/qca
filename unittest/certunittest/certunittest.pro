DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = certunittest
check.commands = ./certunittest

# Input
SOURCES += certunittest.cpp
