QT -= gui
CONFIG += console
CONFIG -= app_bundle
include(../../confapp.pri)
DESTDIR = ../../bin

INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -lqca

SOURCES += main.cpp

unix:{
	target.path=$$BINDIR
	INSTALLS += target
}
