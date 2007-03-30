TEMPLATE = app
TARGET = cms
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = cms
check.commands = ./cms

# Input
SOURCES += cms.cpp
