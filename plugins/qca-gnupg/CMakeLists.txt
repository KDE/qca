# QCA GnuPG

find_program(QCA_GPG_EXECUTABLE NAMES gpg2 gpg)
if(QCA_GPG_EXECUTABLE)
  enable_plugin("gnupg")

  # we don't moc gpgporc/sprocess.cpp
  set(QCA_GNUPG_MOC_SOURCES qca-gnupg.cpp gpgop.cpp gpgproc/gpgproc.cpp)

  my_automoc(QCA_GNUPG_MOC_SOURCES)

  qt4_wrap_cpp(EXTRA_GNUPG_SOURCES gpgop.h)
  qt4_wrap_cpp(EXTRA_GNUPG_SOURCES gpgproc/gpgproc.h)
  qt4_wrap_cpp(EXTRA_GNUPG_SOURCES gpgproc/sprocess.h)

  add_library(qca-gnupg ${PLUGIN_TYPE} ${QCA_GNUPG_MOC_SOURCES} gpgproc/sprocess.cpp ${EXTRA_GNUPG_SOURCES})
  include_directories(gpgproc)
  target_link_libraries(qca-gnupg ${QT_QTCORE_LIBRARY} ${QCA_LIB_NAME})

  if (WIN32)
    target_link_libraries(qca-gnupg advapi32)
  endif (WIN32)

  install(TARGETS qca-gnupg DESTINATION
          LIBRARY DESTINATION "${QCA_PLUGINS_INSTALL_DIR}"
          ARCHIVE DESTINATION "${QCA_PLUGINS_INSTALL_DIR}"
          RUNTIME DESTINATION "${QCA_PLUGINS_INSTALL_DIR}")

  install_pdb(qca-gnupg ${QCA_PLUGINS_INSTALL_DIR})
elseif(WITH_gnupg_PLUGIN STREQUAL "yes")
  message(FATAL_ERROR "Could not find GnuPG binary")
else(QCA_GPG_EXECUTABLE)
  disable_plugin("gnupg")
endif(QCA_GPG_EXECUTABLE)
