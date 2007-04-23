TEMPLATE = lib
CONFIG += plugin
QT -= gui
CONFIG += crypto
DESTDIR = lib

SOURCES = qca-pkcs11.cpp

windows:{
	# hardcoded location
	PKCS11H_PREFIX = /local

	INCLUDEPATH += $$PKCS11H_PREFIX/include
	LIBS += -L$$PKCS11H_PREFIX/lib
	LIBS += -llibpkcs11-helper-1
}

include(conf.pri)

CONFIG(debug, debug|release) {
	unix:TARGET = $$join(TARGET,,,_debug)
	else:TARGET = $$join(TARGET,,,d)
}
