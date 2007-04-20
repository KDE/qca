DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = symmetrickeyunittest
check.commands = ./symmetrickeyunittest

# Input
SOURCES += symmetrickeyunittest.cpp
