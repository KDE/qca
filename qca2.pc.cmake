prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=@CMAKE_INSTALL_PREFIX@
libdir=@LIB_INSTALL_DIR@
includedir=@CMAKE_INSTALL_PREFIX@/include/QtCrypto

Name: QCA
Description: Qt Cryptographic Architecture library
Version: @QCA_LIB_VERSION_STRING@
Requires: QtCore
Libs: -L${libdir} -lqca
Cflags: -I${includedir}
