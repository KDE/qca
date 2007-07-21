include(../examples.pri)
CONFIG -= console
CONFIG += app_bundle
QT += gui

include(pkcs11configdlg/pkcs11configdlg.pri)

HEADERS += prompter.h   keyselectdlg.h   mylistview.h keystoreview.h
SOURCES += prompter.cpp keyselectdlg.cpp main.cpp

FORMS += keyselect.ui mainwin.ui
RESOURCES += cmssigner.qrc
