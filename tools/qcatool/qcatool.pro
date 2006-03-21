QT -= gui
CONFIG += console
CONFIG -= app_bundle
CONFIG += debug
DESTDIR = ../../bin

INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca

SOURCES += main.cpp

unix:{
	include(../../conf.pri)

	target.path=$$BINDIR
	INSTALLS += target
}
