TEMPLATE = app
TARGET = clientplugin
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = clientplugin
check.commands = ./clientplugin

# Input
SOURCES += clientplugin.cpp
