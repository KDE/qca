TEMPLATE = app
CONFIG += qt warn_on console debug
TARGET = qca-unittest

INCLUDEPATH += ../src
LIBS += -L..

HEADERS += kunittest.h qtester.h tester.h 
SOURCES += kunittest.cpp qtester.cpp main.cpp
LIBS += -lqca

HEADERS += staticunittest.h hashunittest.h bigintunittest.h
HEADERS += securearrayunittest.h macunittest.h randomunittest.h
HEADERS += keylengthunittest.h symmetrickeyunittest.h
HEADERS += cipherunittest.h kdfunittest.h

SOURCES += staticunittest.cpp hashunittest.cpp bigintunittest.cpp
SOURCES += securearrayunittest.cpp macunittest.cpp randomunittest.cpp
SOURCES += keylengthunittest.cpp symmetrickeyunittest.cpp
SOURCES += cipherunittest.cpp kdfunittest.cpp
