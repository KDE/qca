CONFIG -= app_bundle
CONFIG += console
QT     -= gui
QT     += network

HEADERS += tlssocket.h
SOURCES += tlssocket.cpp main.cpp

include(../examples.pri)
