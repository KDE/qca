# qca qmake profile

QCA_BASE = ..
QCA_INCBASE = ../include
QCA_SRCBASE = .

TEMPLATE = lib
#CONFIG  += release
CONFIG  += debug
QT      -= gui
TARGET   = qca
DESTDIR  = $$QCA_BASE/lib

MOC_DIR        = .moc
OBJECTS_DIR    = .obj

VER_MAJ = 2
VER_MIN = 0

# make DLL
windows: {
	CONFIG += dll
	DEFINES += QCA_MAKEDLL
}

QCA_INC = $$QCA_INCBASE/QtCrypto
QCA_CPP = $$QCA_SRCBASE
INCLUDEPATH += $$QCA_INC $$QCA_CPP

# botantools
include($$QCA_SRCBASE/botantools/botantools.pri)

PRIVATE_HEADERS += \
	$$QCA_CPP/qca_plugin.h \
	$$QCA_CPP/qca_systemstore.h

PUBLIC_HEADERS += \
	$$QCA_INC/qca_export.h \
	$$QCA_INC/qca_support.h \
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
	$$QCA_INC/qpipe.h

HEADERS += $$PRIVATE_HEADERS $$PUBLIC_HEADERS

# do support first
SOURCES += $$QCA_CPP/support/synchronizer.cpp
include($$QCA_SRCBASE/support/dirwatch/dirwatch.pri)

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
	$$QCA_CPP/qca_default.cpp \
	$$QCA_CPP/support/qpipe.cpp \
	$$QCA_CPP/support/console.cpp

unix:!mac: {
	SOURCES += $$QCA_CPP/qca_systemstore_flatfile.cpp
}
windows: {
	SOURCES += $$QCA_CPP/qca_systemstore_win.cpp
	LIBS += -lcrypt32
}
mac: {
	SOURCES += $$QCA_CPP/qca_systemstore_mac.cpp
	LIBS += -framework Carbon -framework Security
}

unix: {
	include($$QCA_BASE/conf.pri)

	# install
	target.path = $$LIBDIR
	INSTALLS += target

	incfiles.path = $$PREFIX/include/QtCrypto
	incfiles.files = $$PUBLIC_HEADERS
	incfiles.files += $$QCA_INC/qca.h $$QCA_INC/QtCrypto
	INSTALLS += incfiles
}
