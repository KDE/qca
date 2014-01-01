set(rsatest_bin_SRCS rsatest.cpp)  

add_executable(rsatest ${rsatest_bin_SRCS})

target_link_qca_libraries(rsatest)
