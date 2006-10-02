prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=@CMAKE_INSTALL_PREFIX@
libdir=@CMAKE_INSTALL_PREFIX@/lib
includedir=@CMAKE_INSTALL_PREFIX@/include/QtCrypto

Name: QCA
Description: Qt Cryptographic Architecture library\n
Version: 2.0.0 #maybe this shouldn't be literal...
Requires: QtCore
Libs: -L${libdir} -lqca
Cflags: -I${includedir}
