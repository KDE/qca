DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = rsaunittest
check.commands = ./rsaunittest

# Input
HEADERS += rsaunittest.h
SOURCES += rsaunittest.cpp
