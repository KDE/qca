set(mactest_bin_SRCS mactest.cpp)  

add_executable(mactest ${mactest_bin_SRCS})

target_link_libraries( mactest ${QCA_LIB_NAME} ${QT_QTGUI_LIBRARY})

