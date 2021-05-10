set(saslclient_bin_SRCS saslclient.cpp)  

add_executable(saslclient ${saslclient_bin_SRCS})

target_link_qca_libraries(saslclient)
if(QT6)
  target_link_libraries(saslclient Qt6::Network)
else()
  target_link_libraries(saslclient Qt5::Network)
endif()
