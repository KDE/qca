set(saslserver_bin_SRCS saslserver.cpp)  

add_executable(saslserver ${saslserver_bin_SRCS})

target_link_qca_libraries(saslserver)
if(QT6)
  target_link_libraries(saslserver Qt6::Network)
else()
  target_link_libraries(saslserver Qt5::Network)
endif()
