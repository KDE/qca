DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = symmetrickeyunittest
test.commands = ./symmetrickeyunittest

# Input
SOURCES += symmetrickeyunittest.cpp
