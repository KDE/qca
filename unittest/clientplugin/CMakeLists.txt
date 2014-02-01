ENABLE_TESTING()

set( clientplugin_bin_SRCS clientplugin.cpp )

MY_AUTOMOC( clientplugin_bin_SRCS )

add_executable(clientplugin ${clientplugin_bin_SRCS} )

target_link_qca_test_libraries(clientplugin)

add_qca_test(clientplugin "ClientSidePlugin")
