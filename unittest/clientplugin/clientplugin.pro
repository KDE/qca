TEMPLATE = app
TARGET = clientplugin
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = clientplugin
check.commands = ./clientplugin

# Input
SOURCES += clientplugin.cpp
