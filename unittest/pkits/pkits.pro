TEMPLATE = app
TARGET = pkits
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = pkits
check.commands = ./pkits

# Input
HEADERS += pkits.h
SOURCES += pkits.cpp
