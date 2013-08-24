set(hextest_bin_SRCS hextest.cpp)  

add_executable(hextest ${hextest_bin_SRCS})

target_link_libraries( hextest ${QCA_LIB_NAME} ${QT_QTGUI_LIBRARY})

