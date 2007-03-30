TEMPLATE = app
TARGET = keystore
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = keystore
check.commands = ./keystore

# Input
SOURCES += keystore.cpp
