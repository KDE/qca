DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = keystore
check.commands = ./keystore

# Input
SOURCES += keystore.cpp
