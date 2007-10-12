TEMPLATE = lib
CONFIG += plugin
QT -= gui
CONFIG += crypto
DESTDIR = lib

VERSION = 2.0.0

unix:include(conf.pri)
windows:include(conf_win.pri)

CONFIG += create_prl

SOURCES = qca-logger.cpp

!debug_and_release|build_pass {
	CONFIG(debug, debug|release) {
		mac:TARGET = $$member(TARGET, 0)_debug
		windows:TARGET = $$member(TARGET, 0)d
	}
}
