TEMPLATE = lib
CONFIG += plugin
QT -= gui
QT += network
CONFIG += crypto
DESTDIR = lib

# default windows config for now
windows:CONFIG += debug_and_release build_all

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
