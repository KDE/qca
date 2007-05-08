TEMPLATE = lib
CONFIG += plugin
QT -= gui
CONFIG += crypto
DESTDIR = lib

VERSION = 1.0.0

include(conf.pri)

# default windows config for now
windows:CONFIG += debug_and_release build_all

SOURCES = qca-pkcs11.cpp

windows:{
	# hardcoded location
	PKCS11H_PREFIX = /local

	INCLUDEPATH += $$PKCS11H_PREFIX/include
	LIBS += -L$$PKCS11H_PREFIX/lib
	LIBS += -lpkcs11-helper.dll
}

CONFIG(debug, debug|release) {
	unix:TARGET = $$join(TARGET,,,_debug)
	else:TARGET = $$join(TARGET,,,d)
}
