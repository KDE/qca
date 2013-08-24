set(saslserver_bin_SRCS saslserver.cpp)  

MY_AUTOMOC( saslserver_bin_SRCS)

add_executable(saslserver ${saslserver_bin_SRCS})

target_link_libraries( saslserver ${QCA_LIB_NAME} ${QT_QTGUI_LIBRARY} ${QT_QTNETWORK_LIBRARY})
