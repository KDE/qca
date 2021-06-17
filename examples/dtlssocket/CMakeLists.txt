add_executable(dtlssocket dtlssocket.cpp main.cpp)

target_link_qca_libraries(dtlssocket)
if(QT6)
  target_link_libraries(dtlssocket Qt6::Network)
else()
  target_link_libraries(dtlssocket Qt5::Network)
endif()
