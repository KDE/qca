set(saslclient_bin_SRCS saslclient.cpp)  

MY_AUTOMOC( saslclient_bin_SRCS)

add_executable(saslclient ${saslclient_bin_SRCS})

target_link_libraries( saslclient ${QCA_LIB_NAME} ${QT_QTGUI_LIBRARY} ${QT_QTNETWORK_LIBRARY})
