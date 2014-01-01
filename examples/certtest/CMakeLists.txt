set(certtest_bin_SRCS certtest.cpp)  

add_executable(certtest ${certtest_bin_SRCS})

target_link_qca_libraries(certtest)
