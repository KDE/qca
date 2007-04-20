DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = filewatchunittest
check.commands = ./filewatchunittest

# Input
HEADERS += filewatchunittest.h
SOURCES += filewatchunittest.cpp
