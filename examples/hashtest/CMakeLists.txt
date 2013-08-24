set(hashtest_bin_SRCS hashtest.cpp)  

add_executable(hashtest ${hashtest_bin_SRCS})

target_link_libraries( hashtest ${QCA_LIB_NAME} ${QT_QTGUI_LIBRARY})

