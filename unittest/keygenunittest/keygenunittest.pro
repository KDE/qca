TEMPLATE = app
TARGET = keygenunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
# check target

QMAKE_EXTRA_TARGETS = check
check.depends = keygenunittest
check.commands = ./keygenunittest

# Input
SOURCES += keygenunittest.cpp
