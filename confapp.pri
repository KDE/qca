unix:include(confapp_unix.pri)
windows:include(confapp_win.pri)

QCA_LIBNAME = qca
CONFIG(debug, debug|release) {
	windows:QCA_LIBNAME = qcad
	mac:QCA_LIBNAME = qca_debug
}
