set(base64test_bin_SRCS base64test.cpp)  

add_executable(base64test ${base64test_bin_SRCS})

target_link_libraries( base64test ${QCA_LIB_NAME} ${QT_QTCORE_LIBRARY})

