# qca qmake profile

TEMPLATE = lib
CONFIG += qt thread release
TARGET = qca

MOC_DIR        = .moc
OBJECTS_DIR    = .obj
UI_DIR         = .ui

VER_MAJ = 1
VER_MIN = 0

# make DLL
win32:{
	CONFIG += dll
	DEFINES += QCA_MAKEDLL
}

QCA_CPP = src
INCLUDEPATH += $$QCA_CPP

# botantools
include(src/botantools/botantools.pri)

HEADERS += \
	$$QCA_CPP/qca.h \
	$$QCA_CPP/qcaprovider.h

SOURCES += \
	$$QCA_CPP/qca.cpp \
	$$QCA_CPP/qca_tools.cpp

include(conf.pri)
include(extra.pri)

