TEMPLATE = app
CONFIG += thread
TARGET = hashtest

MOC_DIR     = .moc
OBJECTS_DIR = .obj
UI_DIR      = .ui

INCLUDEPATH += src
INCLUDEPATH += plugins
HEADERS += src/qca.h
SOURCES += hashtest.cpp src/qca.cpp

