TEMPLATE = app
TARGET = base64unittest
DEPENDPATH += .
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca
CONFIG += qtestlib thread console
# check target

QMAKE_EXTRA_TARGETS = check
check.depends = base64unittest
check.commands = ./base64unittest

# Input
HEADERS += base64unittest.h
SOURCES += base64unittest.cpp
