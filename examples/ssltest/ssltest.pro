TEMPLATE = app
CONFIG += thread
TARGET = ssltest

INCLUDEPATH += ../common
HEADERS += ../common/base64.h
SOURCES += ../common/base64.cpp ssltest.cpp
include(../examples.pri)
