ENABLE_TESTING()

set( clientplugin_bin_SRCS clientplugin.cpp )

MY_AUTOMOC( clientplugin_bin_SRCS )

add_executable(clientplugin ${clientplugin_bin_SRCS} )

target_link_libraries( clientplugin ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST(ClientSidePlugin ${EXECUTABLE_OUTPUT_PATH}/clientplugin)
