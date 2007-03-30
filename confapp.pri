unix:{
	include(confapp_unix.pri)
}
windows:{
	CONFIG += debug
	QCA_LIBNAME = qca_debug
}
