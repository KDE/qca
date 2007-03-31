TEMPLATE = lib
CONFIG += plugin
QT -= gui
CONFIG += crypto

SOURCES = qca-pkcs11.cpp

windows:{
	# hardcoded openssl location
	OPENSSL_PREFIX = /local
	DEFINES += OSSL_097

	INCLUDEPATH += $$OPENSSL_PREFIX/include
	LIBS += -L$$OPENSSL_PREFIX/lib
	LIBS += -llibeay32 -lssleay32
	LIBS += -lgdi32 -lwsock32
}

include(conf.pri)

CONFIG(debug, debug|release) {
	unix:TARGET = $$join(TARGET,,,_debug)
	else:TARGET = $$join(TARGET,,,d)
}
