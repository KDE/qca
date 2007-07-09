DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib
TARGET = metatypeunittest

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = metatypeunittest
test.commands = ./metatypeunittest

# Input
SOURCES += metatype.cpp
