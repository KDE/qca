# qca-softstore

enable_plugin("softstore")
set(QCA_SOFTSTORE_SOURCES qca-softstore.cpp)
my_automoc( QCA_SOFTSTORE_SOURCES )

add_library(qca-softstore ${PLUGIN_TYPE} ${QCA_SOFTSTORE_SOURCES})

if(APPLE AND ${PLUGIN_TYPE} STREQUAL "MODULE")
  set_property(TARGET qca-softstore PROPERTY SUFFIX ".dylib")
endif()

add_definitions(${SOFTSTOREH_DEFINITIONS})
include_directories(${SOFTSTOREH_INCLUDE_DIR})
target_link_libraries(qca-softstore ${QT_QTCORE_LIBRARY})
target_link_libraries(qca-softstore ${QCA_LIB_NAME})

if(NOT DEVELOPER_MODE)
  install(TARGETS qca-softstore
          LIBRARY DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
          ARCHIVE DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
          RUNTIME DESTINATION "${QCA_CRYPTO_INSTALL_DIR}")

  install_pdb(qca-softstore ${QCA_CRYPTO_INSTALL_DIR})
endif()
