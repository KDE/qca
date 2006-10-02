set(rsatest_bin_SRCS rsatest.cpp)  

add_executable(rsatest ${rsatest_bin_SRCS})

target_link_libraries( rsatest qca ${QT_QTGUI_LIBRARY})

