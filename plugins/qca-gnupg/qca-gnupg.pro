TEMPLATE = lib
CONFIG += plugin
QT -= gui
CONFIG += crypto
DESTDIR = lib

VERSION = 1.0.0

include(conf.pri)

# default windows config for now
windows:CONFIG += debug_and_release build_all

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

CONFIG(debug, debug|release) {
	unix:TARGET = $$join(TARGET,,,_debug)
	else:TARGET = $$join(TARGET,,,d)
}
