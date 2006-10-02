set(hextest_bin_SRCS hextest.cpp)  

add_executable(hextest ${hextest_bin_SRCS})

target_link_libraries( hextest qca ${QT_QTGUI_LIBRARY})

