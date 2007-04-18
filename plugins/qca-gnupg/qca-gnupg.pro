TEMPLATE = lib
CONFIG += plugin
QT -= gui
CONFIG += crypto
DESTDIR = lib

VERSION = 0.0.1

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

include(conf.pri)

CONFIG(debug, debug|release) {
	unix:TARGET = $$join(TARGET,,,_debug)
	else:TARGET = $$join(TARGET,,,d)
}
