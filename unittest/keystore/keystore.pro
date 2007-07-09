DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = keystore
test.commands = ./keystore

# Input
SOURCES += keystore.cpp
