DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib
TARGET = metatypeunittest

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = metatypeunittest
check.commands = ./metatypeunittest

# Input
SOURCES += metatype.cpp
