set(ssltest_bin_SRCS ssltest.cpp)  

QT4_GENERATE_MOC( ssltest.cpp ssltest.moc )

add_executable(ssltest ${ssltest_bin_SRCS})

target_link_libraries( ssltest qca ${QT_QTGUI_LIBRARY})

