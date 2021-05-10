if(WITH_cyrus-sasl_PLUGIN STREQUAL "yes")
  find_package(Sasl2 REQUIRED)
else()
  find_package(Sasl2)
endif()

if(SASL2_FOUND)
  enable_plugin("cyrus-sasl")

  set(QCA_SASL_SOURCES qca-cyrus-sasl.cpp)
  include_directories( ${SASL2_INCLUDE_DIR} )
  add_library(qca-cyrus-sasl ${PLUGIN_TYPE} ${QCA_SASL_SOURCES})

  if(APPLE AND ${PLUGIN_TYPE} STREQUAL "MODULE")
    set_property(TARGET qca-cyrus-sasl PROPERTY SUFFIX ".dylib")
  endif()

  if(QT6)
    target_link_libraries(qca-cyrus-sasl Qt6::Core ${QCA_LIB_NAME} ${SASL2_LIBRARIES})
  else()
    target_link_libraries(qca-cyrus-sasl Qt5::Core ${QCA_LIB_NAME} ${SASL2_LIBRARIES})
  endif()

  if(NOT DEVELOPER_MODE)
    install(TARGETS qca-cyrus-sasl
            LIBRARY DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            ARCHIVE DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            RUNTIME DESTINATION "${QCA_CRYPTO_INSTALL_DIR}")

    install_pdb(qca-cyrus-sasl ${QCA_CRYPTO_INSTALL_DIR})
  endif()
else()
  disable_plugin("cyrus-sasl")
endif()
