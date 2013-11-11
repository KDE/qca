if(WITH_botan_PLUGIN STREQUAL "yes")
  find_package(Botan REQUIRED)
else(WITH_botan_PLUGIN STREQUAL "yes")
  find_package(Botan)
endif(WITH_botan_PLUGIN STREQUAL "yes")

if(BOTAN_FOUND)
  set(WITH_botan_PLUGIN "yes" PARENT_SCOPE)

  set(QCA_BOTAN_SOURCES qca-botan.cpp)
  add_definitions(${BOTAN_CFLAGS})
  my_automoc(QCA_BOTAN_SOURCES)
  add_library(qca-botan MODULE ${QCA_BOTAN_SOURCES})
  target_link_libraries(qca-botan ${QT_QTCORE_LIBRARY} ${QCA_LIB_NAME} ${BOTAN_LIBRARIES})

  install(TARGETS qca-botan
          LIBRARY DESTINATION "${QCA_PLUGINS_INSTALL_DIR}"
          ARCHIVE DESTINATION "${QCA_PLUGINS_INSTALL_DIR}"
          RUNTIME DESTINATION "${QCA_PLUGINS_INSTALL_DIR}")
else(BOTAN_FOUND)
  set(WITH_botan_PLUGIN "no" PARENT_SCOPE)
endif(BOTAN_FOUND)
