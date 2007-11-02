TEMPLATE = lib
CONFIG += plugin
QT -= gui
DESTDIR = lib

VERSION = 2.0.0

unix:include(conf.pri)
windows:CONFIG += crypto
windows:include(conf_win.pri)

CONFIG += create_prl

SOURCES = qca-ossl.cpp

windows:{
	load(winlocal.prf)
	isEmpty(WINLOCAL_PREFIX) {
		error("WINLOCAL_PREFIX not found.  See http://delta.affinix.com/platform/#winlocal")
	}

	OPENSSL_PREFIX = $$WINLOCAL_PREFIX
	DEFINES += OSSL_097

	INCLUDEPATH += $$OPENSSL_PREFIX/include
	LIBS += -L$$OPENSSL_PREFIX/lib
	LIBS += -llibeay32 -lssleay32
	LIBS += -lgdi32 -lwsock32
}

!debug_and_release|build_pass {
        CONFIG(debug, debug|release) {
                mac:TARGET = $$member(TARGET, 0)_debug
                windows:TARGET = $$member(TARGET, 0)d
        }
}
