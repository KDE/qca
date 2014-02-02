# qca-logger

enable_plugin("logger")
set(QCA_LOGGER_SOURCES qca-logger.cpp)
my_automoc( QCA_LOGGER_SOURCES )

add_library(qca-logger ${PLUGIN_TYPE} ${QCA_LOGGER_SOURCES})

add_definitions(${LOGGERH_DEFINITIONS})
include_directories(${LOGGERH_INCLUDE_DIR})
target_link_libraries(qca-logger ${QT_QTCORE_LIBRARY})
target_link_libraries(qca-logger ${QCA_LIB_NAME})

install(TARGETS qca-logger
        LIBRARY DESTINATION "${QCA_PLUGINS_INSTALL_DIR}"
        ARCHIVE DESTINATION "${QCA_PLUGINS_INSTALL_DIR}"
        RUNTIME DESTINATION "${QCA_PLUGINS_INSTALL_DIR}")

install_pdb(qca-logger ${QCA_PLUGINS_INSTALL_DIR})
