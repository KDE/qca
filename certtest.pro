TEMPLATE = app
CONFIG += thread
TARGET = certtest

MOC_DIR     = .moc
OBJECTS_DIR = .obj
UI_DIR      = .ui

INCLUDEPATH += src
INCLUDEPATH += plugins
HEADERS += base64.h src/qca.h
SOURCES += base64.cpp certtest.cpp src/qca.cpp

