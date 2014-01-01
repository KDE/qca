set(ssltest_bin_SRCS ssltest.cpp)  

MY_AUTOMOC( ssltest_bin_SRCS)

add_executable(ssltest ${ssltest_bin_SRCS})

target_link_qca_libraries(ssltest)
target_link_libraries(ssltest ${QT_QTNETWORK_LIBRARY})
