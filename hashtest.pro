TEMPLATE = app
INCLUDEPATH += src
INCLUDEPATH += plugins
HEADERS += src/qca.h
SOURCES += hashtest.cpp src/qca.cpp
TARGET = hashtest

# compile in openssl?
DEFINES += USE_OPENSSL
HEADERS += plugins/qcaopenssl.h plugins/qcaopenssl_p.h
SOURCES += plugins/qcaopenssl.cpp
LIBS += -lssl -lcrypto

