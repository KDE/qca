TEMPLATE = app
CONFIG += thread
TARGET = rsatest

MOC_DIR     = .moc
OBJECTS_DIR = .obj
UI_DIR      = .ui

INCLUDEPATH += src
INCLUDEPATH += plugins
HEADERS += src/qca.h
SOURCES += rsatest.cpp src/qca.cpp

