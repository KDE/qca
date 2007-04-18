TEMPLATE = lib
CONFIG += plugin
QT -= gui
QT += network
CONFIG += crypto
DESTDIR = lib

VERSION = 0.0.1

SOURCES = qca-cyrus-sasl.cpp

windows:{
	# hardcoded cyrus sasl location
	INCLUDEPATH += "c:\local\include"
	LIBS += "c:\local\lib\libsasl.lib"
}

include(conf.pri)

CONFIG(debug, debug|release) {
        unix:TARGET = $$join(TARGET,,,_debug)
        else:TARGET = $$join(TARGET,,,d)
}
