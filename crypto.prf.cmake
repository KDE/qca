QCA_INCDIR = @CRYPTO_PRF_RELATIVE_PATH@@QCA_INCLUDE_INSTALL_DIR@
QCA_LIBDIR = @CRYPTO_PRF_RELATIVE_PATH@@QCA_LIBRARY_INSTALL_DIR@

CONFIG *= qt

LINKAGE =

exists($$QCA_LIBDIR/qca.framework) {
	QMAKE_CXXFLAGS += -F$$QCA_LIBDIR
	LIBS *= -F$$QCA_LIBDIR
	INCLUDEPATH += $$QCA_LIBDIR/qca.framework/Headers
	LINKAGE = -framework qca
}

# else, link normally
isEmpty(LINKAGE) {
	INCLUDEPATH += $$QCA_INCDIR/QtCrypto
	LIBS += -L$$QCA_LIBDIR
	LINKAGE = -lqca
	CONFIG(debug, debug|release) {
		windows:LINKAGE = -lqcad
		mac:LINKAGE = -lqca_debug
	}
}

LIBS += $$LINKAGE
