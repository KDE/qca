TEMPLATE = app
TARGET = tlsunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = tlsunittest
check.commands = ./tlsunittest

# Input
SOURCES += tlsunittest.cpp
