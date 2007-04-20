QT += network

SOURCES += saslservtest.cpp
include(../examples.pri)

windows:LIBS += -lws2_32
