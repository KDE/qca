TEMPLATE = app
CONFIG += thread
TARGET = sasltest

MOC_DIR     = .moc
OBJECTS_DIR = .obj
UI_DIR      = .ui

INCLUDEPATH += src
INCLUDEPATH += plugins
HEADERS += src/qca.h
SOURCES += sasltest.cpp src/qca.cpp

