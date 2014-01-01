set(hashtest_bin_SRCS hashtest.cpp)  

add_executable(hashtest ${hashtest_bin_SRCS})

target_link_qca_libraries(hashtest)
