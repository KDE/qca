TEMPLATE = app
CONFIG += qt warn_on console
TARGET = qca-unittest

INCLUDEPATH += ../src
LIBS += -L..

HEADERS += kunittest.h qtester.h tester.h 
SOURCES += kunittest.cpp qtester.cpp main.cpp
LIBS += -lqca

HEADERS += staticunittest.h hashunittest.h bigintunittest.h
SOURCES +=  staticunittest.cpp hashunittest.cpp bigintunittest.cpp
