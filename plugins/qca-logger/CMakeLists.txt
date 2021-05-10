# qca-logger

enable_plugin("logger")
set(QCA_LOGGER_SOURCES qca-logger.cpp)

add_library(qca-logger ${PLUGIN_TYPE} ${QCA_LOGGER_SOURCES})

if(APPLE AND ${PLUGIN_TYPE} STREQUAL "MODULE")
  set_property(TARGET qca-logger PROPERTY SUFFIX ".dylib")
endif()

add_definitions(${LOGGERH_DEFINITIONS})
include_directories(${LOGGERH_INCLUDE_DIR})
if(QT6)
  target_link_libraries(qca-logger Qt6::Core)
else()
  target_link_libraries(qca-logger Qt5::Core)
endif()

target_link_libraries(qca-logger ${QCA_LIB_NAME})

if(NOT DEVELOPER_MODE)
  install(TARGETS qca-logger
          LIBRARY DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
          ARCHIVE DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
          RUNTIME DESTINATION "${QCA_CRYPTO_INSTALL_DIR}")

  install_pdb(qca-logger ${QCA_CRYPTO_INSTALL_DIR})
endif()
