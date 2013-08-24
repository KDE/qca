prefix=@QCA_PREFIX_INSTALL_DIR@
exec_prefix=@QCA_PREFIX_INSTALL_DIR@
libdir=@QCA_LIBRARY_INSTALL_DIR@
includedir=@QCA_INCLUDE_INSTALL_DIR@/QtCrypto

Name: QCA
Description: Qt Cryptographic Architecture library
Version: @QCA_LIB_VERSION_STRING@
Requires: QtCore
Libs: -L${libdir} -l@QCA_LIB_NAME@
Cflags: -I${includedir}
