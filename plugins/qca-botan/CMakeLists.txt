find_package(PkgConfig REQUIRED)
if(WITH_botan_PLUGIN STREQUAL "yes")
  pkg_check_modules(BOTAN REQUIRED IMPORTED_TARGET botan-2)
else()
  pkg_check_modules(BOTAN IMPORTED_TARGET botan-2)
endif()

if(BOTAN_FOUND)
  enable_plugin("botan")

  set(QCA_BOTAN_SOURCES qca-botan.cpp)
  add_library(qca-botan ${PLUGIN_TYPE} ${QCA_BOTAN_SOURCES})

  if(APPLE AND ${PLUGIN_TYPE} STREQUAL "MODULE")
    set_property(TARGET qca-botan  PROPERTY SUFFIX ".dylib")
  endif()

  target_link_libraries(qca-botan Qt5::Core ${QCA_LIB_NAME} PkgConfig::BOTAN)

  if(NOT DEVELOPER_MODE)
    install(TARGETS qca-botan
            LIBRARY DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            ARCHIVE DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            RUNTIME DESTINATION "${QCA_CRYPTO_INSTALL_DIR}")

    install_pdb(qca-botan ${QCA_CRYPTO_INSTALL_DIR})
  endif()

else()
  disable_plugin("botan")
endif()
