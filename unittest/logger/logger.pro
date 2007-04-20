DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = loggerunittest
check.commands = ./loggerunittest

# Input
SOURCES += loggerunittest.cpp
