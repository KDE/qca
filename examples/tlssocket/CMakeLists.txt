add_executable(tlssocket tlssocket.cpp main.cpp)

target_link_qca_libraries(tlssocket)
target_link_libraries(tlssocket Qt${QT_MAJOR_VERSION}::Network)
