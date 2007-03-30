TEMPLATE = app
TARGET = cipherunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = cipherunittest
check.commands = ./cipherunittest

# Input
SOURCES += cipherunittest.cpp
