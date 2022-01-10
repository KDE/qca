set(saslserver_bin_SRCS saslserver.cpp)  

add_executable(saslserver ${saslserver_bin_SRCS})

target_link_qca_libraries(saslserver)
target_link_libraries(saslserver Qt${QT_MAJOR_VERSION}::Network)
