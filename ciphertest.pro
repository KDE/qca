TEMPLATE = app
CONFIG += thread
TARGET = ciphertest

MOC_DIR     = .moc
OBJECTS_DIR = .obj
UI_DIR      = .ui

INCLUDEPATH += src
INCLUDEPATH += plugins
HEADERS += src/qca.h
SOURCES += ciphertest.cpp src/qca.cpp

