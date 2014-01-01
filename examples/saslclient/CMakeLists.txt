set(saslclient_bin_SRCS saslclient.cpp)  

MY_AUTOMOC( saslclient_bin_SRCS)

add_executable(saslclient ${saslclient_bin_SRCS})

target_link_qca_libraries(saslclient)
target_link_libraries(saslclient ${QT_QTNETWORK_LIBRARY})
