TEMPLATE = app
CONFIG += thread
TARGET = hashtest

MOC_DIR     = .moc
OBJECTS_DIR = .obj
UI_DIR      = .ui

INCLUDEPATH += src
INCLUDEPATH += plugins
HEADERS += src/qca.h src/qcaprovider.h
SOURCES += hashtest.cpp src/qca.cpp

#DEFINES += USE_OPENSSL
#SOURCES += plugins/qcaopenssl.cpp
#LIBS += -lcrypto -lssl

