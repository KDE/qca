DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = metatypeunittest
check.commands = ./metatypeunittest

# Input
SOURCES += metatypeunittest.cpp
