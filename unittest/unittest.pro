TEMPLATE = app
CONFIG += qt warn_on console
TARGET = qca-unittest

HEADERS += kunittest.h qtester.h tester.h staticunittest.h hashunittest.h
SOURCES += kunittest.cpp qtester.cpp main.cpp staticunittest.cpp hashunittest.cpp
LIBS += -lqca
