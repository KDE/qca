TEMPLATE = app
TARGET = keybundle
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = keybundle
check.commands = ./keybundle

# Input
SOURCES += keybundle.cpp
