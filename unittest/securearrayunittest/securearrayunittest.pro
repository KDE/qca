TEMPLATE = app
TARGET = securearrayunittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = securearrayunittest
check.commands = ./securearrayunittest

# Input
HEADERS += securearrayunittest.h
SOURCES += securearrayunittest.cpp
