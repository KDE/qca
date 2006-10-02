set(sslservtest_bin_SRCS sslservtest.cpp)  

add_executable(sslservtest ${sslservtest_bin_SRCS})

target_link_libraries( sslservtest qca ${QT_QTGUI_LIBRARY})

