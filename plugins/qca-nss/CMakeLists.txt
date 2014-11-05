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

  if(APPLE AND ${PLUGIN_TYPE} STREQUAL "MODULE")
    set_property(TARGET qca-nss PROPERTY SUFFIX ".dylib")
  endif()

  if(NOT DEVELOPER_MODE)
    install(TARGETS qca-nss
            LIBRARY DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            ARCHIVE DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            RUNTIME DESTINATION "${QCA_CRYPTO_INSTALL_DIR}")

    install_pdb(qca-nss ${QCA_CRYPTO_INSTALL_DIR})
  endif()
else(NSS_FOUND)
  disable_plugin("nss")
  set(WITH_nss_PLUGIN "no" PARENT_SCOPE)
endif(NSS_FOUND)
