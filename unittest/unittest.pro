TEMPLATE = app
CONFIG += qt warn_on console debug
QT -=gui
TARGET = qca-unittest

INCLUDEPATH += ../include/QtCrypto
LIBS += -L..

HEADERS += kunittest.h tester.h 
SOURCES += kunittest.cpp main.cpp
LIBS += -lqca

HEADERS += randomunittest.h hexunittest.h bigintunittest.h
HEADERS += keylengthunittest.h symmetrickeyunittest.h
HEADERS += staticunittest.h hashunittest.h
HEADERS += securearrayunittest.h
HEADERS += macunittest.h
HEADERS += cipherunittest.h kdfunittest.h
HEADERS += base64unittest.h certunittest.h

SOURCES += randomunittest.cpp hexunittest.cpp bigintunittest.cpp
SOURCES += keylengthunittest.cpp symmetrickeyunittest.cpp
SOURCES += staticunittest.cpp hashunittest.cpp
SOURCES += securearrayunittest.cpp
SOURCES += macunittest.cpp
SOURCES += cipherunittest.cpp kdfunittest.cpp
SOURCES += base64unittest.cpp certunittest.cpp
