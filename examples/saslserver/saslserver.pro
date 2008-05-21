QT += network

SOURCES += saslserver.cpp
include(../examples.pri)

windows:LIBS += -lws2_32
