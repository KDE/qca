TEMPLATE = lib
CONFIG += plugin
QT -= gui
QT += network
CONFIG += crypto
DESTDIR = lib

VERSION = 1.0.0

include(conf.pri)

# default windows config for now
windows:CONFIG += debug_and_release build_all

SOURCES = qca-cyrus-sasl.cpp

windows:{
	# hardcoded cyrus sasl location
	INCLUDEPATH += "c:\local\include"
	LIBS += "c:\local\lib\libsasl.lib"
}

CONFIG(debug, debug|release) {
        unix:TARGET = $$join(TARGET,,,_debug)
        else:TARGET = $$join(TARGET,,,d)
}
