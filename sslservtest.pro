TEMPLATE = app
CONFIG += thread
TARGET = sslservtest

MOC_DIR     = .moc
OBJECTS_DIR = .obj
UI_DIR      = .ui

INCLUDEPATH += src
INCLUDEPATH += plugins
HEADERS += src/qca.h
SOURCES += sslservtest.cpp src/qca.cpp

