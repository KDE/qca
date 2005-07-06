QT -= gui
CONFIG += console
CONFIG -= app_bundle
DESTDIR = ../../bin

INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../.. -lqca

SOURCES += main.cpp

unix:{
	include(../../conf.pri)

	target.path=$$BINDIR
	INSTALLS += target
}
