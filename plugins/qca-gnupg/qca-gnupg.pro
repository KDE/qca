TEMPLATE = lib
CONFIG += plugin
QT -= gui
DESTDIR = lib

VERSION = 2.0.0

unix:include(conf.pri)
windows:CONFIG += crypto
windows:include(conf_win.pri)

CONFIG += create_prl

windows:LIBS += -ladvapi32

GPG_BASE = .
GPGPROC_BASE = $$GPG_BASE/gpgproc
include($$GPGPROC_BASE/gpgproc.pri)
INCLUDEPATH += $$GPGPROC_BASE
INCLUDEPATH += $$GPG_BASE
HEADERS += \
	$$GPG_BASE/gpgop.h
SOURCES += \
	$$GPG_BASE/gpgop.cpp \
	$$GPG_BASE/qca-gnupg.cpp

!debug_and_release|build_pass {
	CONFIG(debug, debug|release) {
		mac:TARGET = $$member(TARGET, 0)_debug
		windows:TARGET = $$member(TARGET, 0)d
	}
}
