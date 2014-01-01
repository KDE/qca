set(ciphertest_bin_SRCS ciphertest.cpp)  

add_executable(ciphertest ${ciphertest_bin_SRCS})

target_link_qca_libraries(ciphertest)
