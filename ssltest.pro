TEMPLATE = app
CONFIG += thread
TARGET = ssltest

MOC_DIR     = .moc
OBJECTS_DIR = .obj
UI_DIR      = .ui

INCLUDEPATH += src
INCLUDEPATH += plugins
HEADERS += base64.h src/qca.h
SOURCES += base64.cpp ssltest.cpp src/qca.cpp

