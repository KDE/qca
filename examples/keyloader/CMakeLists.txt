set(keyloader_bin_SRCS keyloader.cpp)  

MY_AUTOMOC( keyloader_bin_SRCS )

add_executable(keyloader ${keyloader_bin_SRCS})

target_link_qca_libraries(keyloader)
