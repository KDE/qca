# qca-softstore

set(WITH_softstore_PLUGIN "yes" PARENT_SCOPE)
set(QCA_SOFTSTORE_SOURCES qca-softstore.cpp)
my_automoc( QCA_SOFTSTORE_SOURCES )

add_library(qca-softstore MODULE ${QCA_SOFTSTORE_SOURCES})

add_definitions(${SOFTSTOREH_DEFINITIONS})
include_directories(${SOFTSTOREH_INCLUDE_DIR})
target_link_libraries(qca-softstore ${QT_QTCORE_LIBRARY})
target_link_libraries(qca-softstore ${QCA_LIB_NAME})

install(TARGETS qca-softstore
        LIBRARY DESTINATION "${QCA_PLUGINS_INSTALL_DIR}"
        ARCHIVE DESTINATION "${QCA_PLUGINS_INSTALL_DIR}"
        RUNTIME DESTINATION "${QCA_PLUGINS_INSTALL_DIR}")
