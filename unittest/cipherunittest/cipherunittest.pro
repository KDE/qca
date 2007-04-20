DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = cipherunittest
check.commands = ./cipherunittest

# Input
SOURCES += cipherunittest.cpp
