set(keyloader_bin_SRCS keyloader.cpp)  

MY_AUTOMOC( keyloader_bin_SRCS )

add_executable(keyloader ${keyloader_bin_SRCS})

target_link_libraries( keyloader ${QCA_LIB_NAME} ${QT_QTCORE_LIBRARY})

