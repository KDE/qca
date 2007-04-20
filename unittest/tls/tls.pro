DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = tlsunittest
check.commands = ./tlsunittest

# Input
SOURCES += tlsunittest.cpp
