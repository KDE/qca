TEMPLATE = app
CONFIG += thread
TARGET = certtest

INCLUDEPATH += ../common
HEADERS += ../common/base64.h
SOURCES += ../common/base64.cpp certtest.cpp
include(../examples.pri)
