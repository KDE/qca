TEMPLATE = app
TARGET = cms
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = cms
check.commands = ./cms

# Input
HEADERS += cms.h
SOURCES += cms.cpp
