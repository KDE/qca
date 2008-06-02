QT -= gui
CONFIG += console
CONFIG -= app_bundle
include(../../confapp.pri)
TARGET = qcatool2
DESTDIR = ../../bin

SOURCES += main.cpp

unix:{
	target.path=$$BINDIR
	INSTALLS += target
}
