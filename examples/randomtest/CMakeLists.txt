set(randomtest_bin_SRCS randomtest.cpp)  

add_executable(randomtest ${randomtest_bin_SRCS})

target_link_qca_libraries(randomtest)
