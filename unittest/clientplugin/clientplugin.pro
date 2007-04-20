DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = clientplugin
check.commands = ./clientplugin

# Input
SOURCES += clientplugin.cpp
