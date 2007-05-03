include(../examples.pri)
CONFIG -= console
CONFIG += app_bundle
QT += gui

HEADERS += mylistview.h keystoreview.h
SOURCES += main.cpp

FORMS += mainwin.ui loadstore.ui modconfig.ui
RESOURCES += cmssigner.qrc
