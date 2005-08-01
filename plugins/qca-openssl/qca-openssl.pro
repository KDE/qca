#CONFIG += release
CONFIG += debug

TEMPLATE = lib
CONFIG += plugin
QT -= gui
CONFIG += crypto

SOURCES = qca-openssl.cpp
#SOURCES += main.cpp

windows:{
	# hardcoded openssl location
	OPENSSL_PREFIX = /local

	INCLUDEPATH += $$OPENSSL_PREFIX/include
	LIBS += -L$$OPENSSL_PREFIX/lib
	LIBS += -llibeay32 -lssleay32
	LIBS += -lgdi32 -lwsock32
}

include(conf.pri)
