# qca qmake profile

TEMPLATE = lib
CONFIG += qt thread release
TARGET = qca

MOC_DIR        = .moc
OBJECTS_DIR    = .obj
UI_DIR         = .ui

# make DLL
win32:{
	CONFIG += dll
	DEFINES += QCA_MAKEDLL
}

QCA_CPP = src
INCLUDEPATH += $$QCA_CPP

HEADERS += \
	$$QCA_CPP/qca.h \
	$$QCA_CPP/qcaprovider.h

SOURCES += \
	$$QCA_CPP/qca.cpp

include(conf.pri)
include(extra.pri)

