set(aes-cmac_bin_SRCS aes-cmac.cpp)  

add_executable(aes-cmac ${aes-cmac_bin_SRCS})

target_link_libraries( aes-cmac ${QCA_LIB_NAME} ${QT_QTGUI_LIBRARY})

