DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = cms
check.commands = ./cms

# Input
SOURCES += cms.cpp
