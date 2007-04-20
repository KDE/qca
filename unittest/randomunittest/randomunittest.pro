DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = randomunittest
check.commands = ./randomunittest

# Input
SOURCES += randomunittest.cpp
