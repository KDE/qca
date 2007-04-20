DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = pgpunittest
check.commands = ./pgpunittest

# Input
SOURCES += pgpunittest.cpp
