QT -= gui
CONFIG += console
CONFIG -= app_bundle
include(../../confapp.pri)
TARGET = qcatool2
DESTDIR = ../../bin

INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib -l$$QCA_LIBNAME

SOURCES += main.cpp

unix:{
	target.path=$$BINDIR
	INSTALLS += target
}
