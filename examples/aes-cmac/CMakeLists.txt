set(aes-cmac_bin_SRCS aes-cmac.cpp)  

add_executable(aes-cmac ${aes-cmac_bin_SRCS})

target_link_qca_libraries(aes-cmac)
