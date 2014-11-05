if(WITH_botan_PLUGIN STREQUAL "yes")
  find_package(Botan REQUIRED)
else(WITH_botan_PLUGIN STREQUAL "yes")
  find_package(Botan)
endif(WITH_botan_PLUGIN STREQUAL "yes")

if(BOTAN_FOUND)
  enable_plugin("botan")

  set(QCA_BOTAN_SOURCES qca-botan.cpp)
  add_definitions(${BOTAN_CFLAGS})
  my_automoc(QCA_BOTAN_SOURCES)
  add_library(qca-botan ${PLUGIN_TYPE} ${QCA_BOTAN_SOURCES})

  if(APPLE AND ${PLUGIN_TYPE} STREQUAL "MODULE")
    set_property(TARGET qca-botan  PROPERTY SUFFIX ".dylib")
  endif()

  target_link_libraries(qca-botan ${QT_QTCORE_LIBRARY} ${QCA_LIB_NAME} ${BOTAN_LIBRARIES})

  if(NOT DEVELOPER_MODE)
    install(TARGETS qca-botan
            LIBRARY DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            ARCHIVE DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            RUNTIME DESTINATION "${QCA_CRYPTO_INSTALL_DIR}")

    install_pdb(qca-botan ${QCA_CRYPTO_INSTALL_DIR})
  endif()

else(BOTAN_FOUND)
  disable_plugin("botan")
endif(BOTAN_FOUND)
