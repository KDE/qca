include(../examples.pri)
CONFIG -= console
CONFIG += app_bundle
QT += gui

include(pkcs11configdlg/pkcs11configdlg.pri)

HEADERS += mylistview.h keystoreview.h
SOURCES += main.cpp

FORMS += mainwin.ui loadstore.ui
RESOURCES += cmssigner.qrc
