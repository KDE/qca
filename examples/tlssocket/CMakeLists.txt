add_executable(tlssocket tlssocket.cpp main.cpp)

target_link_qca_libraries(tlssocket)
if(QT6)
  target_link_libraries(tlssocket Qt6::Network)
else()
  target_link_libraries(tlssocket Qt5::Network)
endif()
