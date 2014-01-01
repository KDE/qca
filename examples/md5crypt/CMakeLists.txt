set(md5crypt_bin_SRCS md5crypt.cpp)  

add_executable(md5crypt ${md5crypt_bin_SRCS})

target_link_qca_libraries(md5crypt)

#add "crypt" to the libs if you are trying the crypt() equivalent
