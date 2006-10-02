set(ssltest_bin_SRCS ssltest.cpp)  


MY_AUTOMOC( ssltest_bin_SRCS)

add_executable(ssltest ${ssltest_bin_SRCS})

target_link_libraries( ssltest qca ${QT_QTGUI_LIBRARY} ${QT_QTNETWORK_LIBRARY})

