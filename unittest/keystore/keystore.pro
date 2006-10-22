TEMPLATE = app
TARGET = keystore
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = keystore
check.commands = ./keystore

# Input
SOURCES += keystore.cpp
