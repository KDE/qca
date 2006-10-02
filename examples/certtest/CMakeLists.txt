set(certtest_bin_SRCS certtest.cpp)  

add_executable(certtest ${certtest_bin_SRCS})

target_link_libraries( certtest qca ${QT_QTGUI_LIBRARY})

