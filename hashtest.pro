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

# compile in openssl?
#DEFINES += USE_OPENSSL
#HEADERS += plugins/qcaopenssl.h plugins/qcaopenssl_p.h
#SOURCES += plugins/qcaopenssl.cpp
#LIBS += -lssl -lcrypto

