#CONFIG += release
CONFIG += debug

TEMPLATE = lib
CONFIG += plugin
QT -= gui
QT += network
CONFIG += crypto

SOURCES = qca-sasl.cpp

windows:{
	# hardcoded cyrus sasl location
	DEFINES += QCA_PLUGIN_DLL
	INCLUDEPATH += "c:\local\include"
	LIBS += "c:\local\lib\libsasl.lib"
}

include(conf.pri)
