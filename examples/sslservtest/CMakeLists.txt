set(sslservtest_bin_SRCS sslservtest.cpp)  

MY_AUTOMOC( sslservtest_bin_SRCS )

add_executable(sslservtest ${sslservtest_bin_SRCS})

target_link_libraries( sslservtest ${QCA_LIB_NAME} ${QT_QTGUI_LIBRARY} ${QT_QTNETWORK_LIBRARY})

