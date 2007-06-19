TEMPLATE = lib
CONFIG += plugin
QT -= gui
CONFIG += crypto
DESTDIR = lib

SOURCES = qca-test.cpp

include(conf.pri)

CONFIG(debug, debug|release) {
	unix:TARGET = $$join(TARGET,,,_debug)
	else:TARGET = $$join(TARGET,,,d)
}
