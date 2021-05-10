find_package(PkgConfig REQUIRED)
if(WITH_nss_PLUGIN STREQUAL "yes")
  pkg_check_modules(NSS REQUIRED IMPORTED_TARGET nss)
else()
  pkg_check_modules(NSS IMPORTED_TARGET nss)
endif()

if(NSS_FOUND)
  enable_plugin("nss")

  set(QCA_NSS_SOURCES qca-nss.cpp)
  add_library(qca-nss ${PLUGIN_TYPE} ${QCA_NSS_SOURCES})
  if(QT6)
    target_link_libraries(qca-nss Qt6::Core ${QCA_LIB_NAME} PkgConfig::NSS)
  else()
    target_link_libraries(qca-nss Qt5::Core ${QCA_LIB_NAME} PkgConfig::NSS)
  endif()

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
else()
  disable_plugin("nss")
  set(WITH_nss_PLUGIN "no" PARENT_SCOPE)
endif()
