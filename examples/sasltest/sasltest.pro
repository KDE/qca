TEMPLATE = app
CONFIG += thread console
TARGET = sasltest

INCLUDEPATH += ../common
HEADERS += ../common/base64.h
SOURCES += ../common/base64.cpp sasltest.cpp
include(../examples.pri)
