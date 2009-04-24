QT -= gui
CONFIG += console
CONFIG -= app_bundle
include(../../app.pri)
TARGET = qcatool2
DESTDIR = ../../bin

SOURCES += main.cpp

unix:{
	target.path=$$BINDIR
	INSTALLS += target
}
