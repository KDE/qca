TEMPLATE = app
TARGET = filewatchunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = filewatchunittest
check.commands = ./filewatchunittest

# Input
HEADERS += filewatchunittest.h
SOURCES += filewatchunittest.cpp
