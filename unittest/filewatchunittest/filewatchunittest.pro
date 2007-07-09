DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = filewatchunittest
test.commands = ./filewatchunittest

# Input
HEADERS += filewatchunittest.h
SOURCES += filewatchunittest.cpp
