# QCA GnuPG

enable_plugin("gnupg")

set(QCA_GNUPG_MOC_SOURCES
  qca-gnupg.cpp
  gpgop.cpp
  gpgproc/gpgproc.cpp
)

set(QCA_GNUPG_NONMOC_SOURCES
  utils.cpp
  gpgproc/sprocess.cpp
)

my_automoc(QCA_GNUPG_MOC_SOURCES)

qt4_wrap_cpp(EXTRA_GNUPG_SOURCES gpgop.h)
qt4_wrap_cpp(EXTRA_GNUPG_SOURCES gpgproc/gpgproc.h)
qt4_wrap_cpp(EXTRA_GNUPG_SOURCES gpgproc/sprocess.h)

add_library(qca-gnupg ${PLUGIN_TYPE} ${QCA_GNUPG_MOC_SOURCES} ${QCA_GNUPG_NONMOC_SOURCES} ${EXTRA_GNUPG_SOURCES})
include_directories(gpgproc)
target_link_libraries(qca-gnupg ${QT_QTCORE_LIBRARY} ${QCA_LIB_NAME})

if (WIN32)
  target_link_libraries(qca-gnupg advapi32)
endif (WIN32)

if(NOT DEVELOPER_MODE)
  install(TARGETS qca-gnupg DESTINATION
          LIBRARY DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
          ARCHIVE DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
          RUNTIME DESTINATION "${QCA_CRYPTO_INSTALL_DIR}")

  install_pdb(qca-gnupg ${QCA_CRYPTO_INSTALL_DIR})
endif()
