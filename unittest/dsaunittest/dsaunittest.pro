TEMPLATE = app
TARGET = dsaunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = dsaunittest
check.commands = ./dsaunittest

# Input
SOURCES += dsaunittest.cpp
