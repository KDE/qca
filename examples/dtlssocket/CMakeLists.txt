add_executable(dtlssocket dtlssocket.cpp main.cpp)

target_link_qca_libraries(dtlssocket)
target_link_libraries(dtlssocket Qt5::Network)
