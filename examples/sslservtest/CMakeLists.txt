set(sslservtest_bin_SRCS sslservtest.cpp)  

add_executable(sslservtest ${sslservtest_bin_SRCS})

target_link_qca_libraries(sslservtest)
target_link_libraries(sslservtest Qt${QT_MAJOR_VERSION}::Network)
