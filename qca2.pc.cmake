prefix=@QCA_PREFIX_INSTALL_DIR@
exec_prefix=@QCA_PREFIX_INSTALL_DIR@
libdir=@QCA_LIBRARY_INSTALL_DIR@
includedir=@QCA_FULL_INCLUDE_INSTALL_DIR@

Name: QCA
Description: Qt Cryptographic Architecture library
Version: @QCA_LIB_VERSION_STRING@
Requires: @QCA_QT_PC_VERSION@
Libs: @PKGCONFIG_LIBS@
Cflags: @PKGCONFIG_CFLAGS@
