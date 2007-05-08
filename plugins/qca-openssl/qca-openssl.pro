TEMPLATE = lib
CONFIG += plugin
QT -= gui
CONFIG += crypto
DESTDIR = lib

VERSION = 1.0.0

include(conf.pri)

CONFIG += create_prl

# default windows config for now
windows:CONFIG += debug_and_release build_all

SOURCES = qca-openssl.cpp
#SOURCES += main.cpp

windows:{
	CONFIG += winlocal
	OPENSSL_PREFIX = $$WINLOCAL_PREFIX
	DEFINES += OSSL_097

	INCLUDEPATH += $$OPENSSL_PREFIX/include
	LIBS += -L$$OPENSSL_PREFIX/lib
	LIBS += -llibeay32 -lssleay32
	LIBS += -lgdi32 -lwsock32
}

CONFIG(debug, debug|release) {
	unix:TARGET = $$join(TARGET,,,_debug)
	else:TARGET = $$join(TARGET,,,d)
}
