set(mactest_bin_SRCS mactest.cpp)  

add_executable(mactest ${mactest_bin_SRCS})

target_link_qca_libraries(mactest)
