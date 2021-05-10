set(ssltest_bin_SRCS ssltest.cpp)  

add_executable(ssltest ${ssltest_bin_SRCS})

target_link_qca_libraries(ssltest)
if(QT6)
  target_link_libraries(ssltest Qt6::Network)
else()
  target_link_libraries(ssltest Qt5::Network)
endif()
