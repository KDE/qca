if(WITH_nss_PLUGIN STREQUAL "yes")
  find_package(Nss REQUIRED)
else(WITH_nss_PLUGIN STREQUAL "yes")
  find_package(Nss)
endif(WITH_nss_PLUGIN STREQUAL "yes")

if(NSS_FOUND)
  enable_plugin("nss")

  set(QCA_NSS_SOURCES qca-nss.cpp)
  add_definitions(${NSS_CFLAGS_OTHER})
  include_directories(${NSS_INCLUDE_DIRS})
  my_automoc( QCA_NSS_SOURCES )
  add_library(qca-nss ${PLUGIN_TYPE} ${QCA_NSS_SOURCES})
  target_link_libraries(qca-nss ${QT_QTCORE_LIBRARY} ${QCA_LIB_NAME} ${NSS_LDFLAGS})

  install(TARGETS qca-nss
          LIBRARY DESTINATION "${QCA_PLUGINS_INSTALL_DIR}"
          ARCHIVE DESTINATION "${QCA_PLUGINS_INSTALL_DIR}"
          RUNTIME DESTINATION "${QCA_PLUGINS_INSTALL_DIR}")

  install_pdb(qca-nss ${QCA_PLUGINS_INSTALL_DIR})
else(NSS_FOUND)
  disable_plugin("nss")
  set(WITH_nss_PLUGIN "no" PARENT_SCOPE)
endif(NSS_FOUND)
