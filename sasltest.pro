TEMPLATE = app
CONFIG += thread
TARGET = sasltest

MOC_DIR     = .moc
OBJECTS_DIR = .obj
UI_DIR      = .ui

INCLUDEPATH += src
INCLUDEPATH += plugins
HEADERS += src/qca.h base64.h
SOURCES += sasltest.cpp src/qca.cpp base64.cpp

DEFINES += USE_CYRUSSASL
HEADERS += plugins/qcacyrussasl.h
SOURCES += plugins/qcacyrussasl.cpp
LIBS += -lsasl2

