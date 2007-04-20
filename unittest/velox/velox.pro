DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib
QT += network

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = veloxunittest
check.commands = ./veloxunittest

# Input
SOURCES += veloxunittest.cpp
