# qca qmake profile

TEMPLATE = lib
CONFIG  += release
QT      -= gui
TARGET   = qca

MOC_DIR        = .moc
OBJECTS_DIR    = .obj

VER_MAJ = 2
VER_MIN = 0

# make DLL
win: {
	CONFIG += dll
	DEFINES += QCA_MAKEDLL
}

QCA_INC = include/QtCrypto
QCA_CPP = src
INCLUDEPATH += $$QCA_INC $$QCA_CPP

# botantools
include(src/botantools/botantools.pri)

PRIVATE_HEADERS += \
	$$QCA_CPP/qca_plugin.h \
	$$QCA_CPP/qca_systemstore.h

PUBLIC_HEADERS += \
	$$QCA_INC/qca_export.h \
	$$QCA_INC/qca_tools.h \
	$$QCA_INC/qca_core.h \
	$$QCA_INC/qca_textfilter.h \
	$$QCA_INC/qca_basic.h \
	$$QCA_INC/qca_publickey.h \
	$$QCA_INC/qca_cert.h \
	$$QCA_INC/qca_keystore.h \
	$$QCA_INC/qca_securelayer.h \
	$$QCA_INC/qca_securemessage.h \
	$$QCA_INC/qcaprovider.h \

HEADERS += $$PRIVATE_HEADERS $$PUBLIC_HEADERS

SOURCES += \
	$$QCA_CPP/qca_tools.cpp \
	$$QCA_CPP/qca_core.cpp \
	$$QCA_CPP/qca_textfilter.cpp \
	$$QCA_CPP/qca_plugin.cpp \
	$$QCA_CPP/qca_basic.cpp \
	$$QCA_CPP/qca_publickey.cpp \
	$$QCA_CPP/qca_cert.cpp \
	$$QCA_CPP/qca_keystore.cpp \
	$$QCA_CPP/qca_securelayer.cpp \
	$$QCA_CPP/qca_securemessage.cpp \
	$$QCA_CPP/qca_default.cpp

unix:!mac: {
	SOURCES += $$QCA_CPP/qca_systemstore_flatfile.cpp
}
win: {
	SOURCES += $$QCA_CPP/qca_systemstore_win.cpp
}
mac: {
	SOURCES += $$QCA_CPP/qca_systemstore_mac.cpp
	QMAKE_LFLAGS += -framework Carbon
}

include(conf.pri)
include(extra.pri)

