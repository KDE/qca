QCA_INCDIR = @QT_INCLUDE_DIR@
QCA_LIBDIR = @QT_LIBRARY_DIR@

CONFIG *= qt
INCLUDEPATH += $$QCA_INCDIR/QtCrypto
LIBS += -L$$QCA_LIBDIR

LINKAGE = -lqca
CONFIG(debug, debug|release) {
	windows:LINKAGE = -lqcad
	mac:LINKAGE = -lqca_debug
}
LIBS += $$LINKAGE
