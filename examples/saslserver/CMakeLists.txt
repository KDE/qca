set(saslserver_bin_SRCS saslserver.cpp)  

MY_AUTOMOC( saslserver_bin_SRCS)

add_executable(saslserver ${saslserver_bin_SRCS})

target_link_qca_libraries(saslserver)
target_link_libraries(saslserver ${QT_QTNETWORK_LIBRARY})
