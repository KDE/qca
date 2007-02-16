set(md5crypt_bin_SRCS md5crypt.cpp)  

add_executable(md5crypt ${md5crypt_bin_SRCS})

#add "crypt" to the libs if you are trying the crypt() equivalent
target_link_libraries( md5crypt qca ${QT_QTGUI_LIBRARY})

