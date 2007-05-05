unix:include(confapp_unix.pri)
windows:include(confapp_win.pri)

CONFIG(debug, debug|release) {
	unix:QCA_LIBNAME = qca_debug
	else:QCA_LIBNAME = qcad
} else {
	QCA_LIBNAME = qca
}
