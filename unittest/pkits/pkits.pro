TEMPLATE = app
TARGET = pkits
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = pkits
check.commands = ./pkits

# Input
SOURCES += pkits.cpp
