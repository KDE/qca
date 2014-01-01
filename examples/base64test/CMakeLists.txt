set(base64test_bin_SRCS base64test.cpp)  

add_executable(base64test ${base64test_bin_SRCS})

target_link_qca_libraries(base64test)
