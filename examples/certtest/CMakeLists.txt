set(certtest_bin_SRCS certtest.cpp)  

add_executable(certtest ${certtest_bin_SRCS})

target_link_libraries( certtest ${QCA_LIB_NAME} ${QT_QTGUI_LIBRARY})

