DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = pkits
check.commands = ./pkits

# Input
SOURCES += pkits.cpp
