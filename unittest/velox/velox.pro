DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib
QT += network
TARGET = veloxunittest

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = veloxunittest
test.commands = ./veloxunittest

# Input
SOURCES += veloxunittest.cpp
