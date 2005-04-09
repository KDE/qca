TEMPLATE = app
CONFIG += qt warn_on console debug
QT -=gui
TARGET = qca-unittest

#QMAKE_CXXFLAGS_DEBUG += -fprofile-arcs -ftest-coverage

INCLUDEPATH += ../include/QtCrypto
LIBS += -L..
LIBS += -lqca

#DEFINES += QT_STATICPLUGIN
#SOURCES += ../plugins/qca-botan/qca-botan.cpp
#LIBS += -L/usr/lib -lm -lpthread -lrt -lbotan

HEADERS += kunittest.h tester.h 
SOURCES += kunittest.cpp main.cpp

HEADERS += randomunittest.h hexunittest.h bigintunittest.h
HEADERS += keylengthunittest.h symmetrickeyunittest.h
HEADERS += staticunittest.h hashunittest.h
HEADERS += securearrayunittest.h
HEADERS += macunittest.h
HEADERS += cipherunittest.h kdfunittest.h
HEADERS += base64unittest.h certunittest.h
HEADERS += rsaunittest.h
HEADERS += dsaunittest.h

SOURCES += randomunittest.cpp hexunittest.cpp bigintunittest.cpp
SOURCES += keylengthunittest.cpp symmetrickeyunittest.cpp
SOURCES += staticunittest.cpp hashunittest.cpp
SOURCES += securearrayunittest.cpp
SOURCES += macunittest.cpp
SOURCES += cipherunittest.cpp kdfunittest.cpp
SOURCES += base64unittest.cpp certunittest.cpp
SOURCES += rsaunittest.cpp
SOURCES += dsaunittest.cpp
