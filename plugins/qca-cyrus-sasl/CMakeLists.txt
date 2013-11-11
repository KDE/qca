if(WITH_cyrus-sasl_PLUGIN STREQUAL "yes")
  find_package(Sasl2 REQUIRED)
else(WITH_cyrus-sasl_PLUGIN STREQUAL "yes")
  find_package(Sasl2)
endif(WITH_cyrus-sasl_PLUGIN STREQUAL "yes")

if(SASL2_FOUND)
  set(WITH_cyrus-sasl_PLUGIN "yes" PARENT_SCOPE)

  set(QCA_SASL_SOURCES qca-cyrus-sasl.cpp)
  include_directories( ${SASL2_INCLUDE_DIR} )
  my_automoc( QCA_SASL_SOURCES )
  add_library(qca-cyrus-sasl MODULE ${QCA_SASL_SOURCES})
  target_link_libraries(qca-cyrus-sasl ${QT_QTCORE_LIBRARY} ${QCA_LIB_NAME} ${SASL2_LIBRARIES})

  install(TARGETS qca-cyrus-sasl
          LIBRARY DESTINATION "${QCA_PLUGINS_INSTALL_DIR}"
          ARCHIVE DESTINATION "${QCA_PLUGINS_INSTALL_DIR}"
          RUNTIME DESTINATION "${QCA_PLUGINS_INSTALL_DIR}")
else(SASL2_FOUND)
  set(WITH_cyrus-sasl_PLUGIN "no" PARENT_SCOPE)
endif(SASL2_FOUND)
