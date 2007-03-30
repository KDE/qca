TEMPLATE = app
TARGET = symmetrickeyunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = symmetrickeyunittest
check.commands = ./symmetrickeyunittest

# Input
SOURCES += symmetrickeyunittest.cpp
