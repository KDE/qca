find_package(PkgConfig REQUIRED)

pkg_check_modules(BOTAN IMPORTED_TARGET botan-2)
if(NOT BOTAN_FOUND)
  pkg_check_modules(BOTAN IMPORTED_TARGET botan-3)
  if(BOTAN_FOUND)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
  endif()
endif()

if(WITH_botan_PLUGIN STREQUAL "yes" AND NOT BOTAN_FOUND)
  message(FATAL_ERROR "botan requested and not found")
endif()

if(BOTAN_FOUND)
  enable_plugin("botan")

  set(QCA_BOTAN_SOURCES qca-botan.cpp)
  add_library(qca-botan ${PLUGIN_TYPE} ${QCA_BOTAN_SOURCES})

  if(APPLE AND ${PLUGIN_TYPE} STREQUAL "MODULE")
    set_property(TARGET qca-botan  PROPERTY SUFFIX ".dylib")
  endif()

  target_link_libraries(qca-botan Qt${QT_MAJOR_VERSION}::Core ${QCA_LIB_NAME} PkgConfig::BOTAN)

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
