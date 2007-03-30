TEMPLATE = app
TARGET = base64unittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = base64unittest
check.commands = ./base64unittest

# Input
SOURCES += base64unittest.cpp
