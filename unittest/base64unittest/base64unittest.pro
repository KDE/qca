DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = base64unittest
test.commands = ./base64unittest

# Input
SOURCES += base64unittest.cpp
