include(../examples.pri)
CONFIG -= console
CONFIG += app_bundle
QT += gui

include(pkcs11configdlg/pkcs11configdlg.pri)

HEADERS += \
	prompter.h \
	certviewdlg.h \
	keyselectdlg.h

SOURCES += \
	prompter.cpp \
	certviewdlg.cpp \
	keyselectdlg.cpp \
	main.cpp

FORMS += certview.ui keyselect.ui mainwin.ui
RESOURCES += cmssigner.qrc
