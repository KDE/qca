DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = dsaunittest
check.commands = ./dsaunittest

# Input
SOURCES += dsaunittest.cpp
