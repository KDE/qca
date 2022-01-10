set(saslclient_bin_SRCS saslclient.cpp)  

add_executable(saslclient ${saslclient_bin_SRCS})

target_link_qca_libraries(saslclient)
target_link_libraries(saslclient Qt${QT_MAJOR_VERSION}::Network)
