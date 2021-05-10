set(sslservtest_bin_SRCS sslservtest.cpp)  

add_executable(sslservtest ${sslservtest_bin_SRCS})

target_link_qca_libraries(sslservtest)
if(QT6)
  target_link_libraries(sslservtest Qt6::Network)
else()
  target_link_libraries(sslservtest Qt5::Network)
endif()
