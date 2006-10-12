set( clientplugin_bin_SRCS clientplugin.cpp )

MY_AUTOMOC( clientplugin_bin_SRCS )

add_executable(clientplugin ${clientplugin_bin_SRCS} )

target_link_libraries( clientplugin qca ${QT_QTTEST_LIBRARY})

