set(rsatest_bin_SRCS rsatest.cpp)  

add_executable(rsatest ${rsatest_bin_SRCS})

target_link_libraries( rsatest ${QCA_LIB_NAME} ${QT_QTGUI_LIBRARY})

