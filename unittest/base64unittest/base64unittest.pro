DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = base64unittest
check.commands = ./base64unittest

# Input
SOURCES += base64unittest.cpp
