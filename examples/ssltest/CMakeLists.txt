set(ssltest_bin_SRCS ssltest.cpp)  

add_executable(ssltest ${ssltest_bin_SRCS})

target_link_qca_libraries(ssltest)
target_link_libraries(ssltest Qt${QT_MAJOR_VERSION}::Network)
