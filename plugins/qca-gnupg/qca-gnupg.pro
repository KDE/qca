TEMPLATE = lib
CONFIG += plugin
QT -= gui

#CONFIG += release
CONFIG += debug

QCA_INC = ../../include/QtCrypto
QCA_LIB = ../..

INCLUDEPATH += $$QCA_INC
LIBS += -L$$QCA_LIB -lqca

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

#include(conf.pri)
#include(extra.pri)
