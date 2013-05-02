QCA_INCDIR = @CMAKE_INSTALL_PREFIX@/include
QCA_LIBDIR = @LIB_INSTALL_DIR@

CONFIG *= qt
INCLUDEPATH += $$QCA_INCDIR/QtCrypto
LIBS += -L$$QCA_LIBDIR

LINKAGE = -lqca
CONFIG(debug, debug|release) {
	windows:LINKAGE = -lqcad
	mac:LINKAGE = -lqca_debug
}
LIBS += $$LINKAGE
