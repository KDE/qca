DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib

# test target
QMAKE_EXTRA_TARGETS = test
test.depends = cms
test.commands = ./cms

# Input
SOURCES += cms.cpp
