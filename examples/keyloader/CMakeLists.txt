set(keyloader_bin_SRCS keyloader.cpp)  

add_executable(keyloader ${keyloader_bin_SRCS})

target_link_qca_libraries(keyloader)
