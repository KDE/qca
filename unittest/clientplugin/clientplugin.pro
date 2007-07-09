DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = clientplugin
test.commands = ./clientplugin

# Input
SOURCES += clientplugin.cpp
