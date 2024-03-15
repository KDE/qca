set(dtlssocket_bin_SRCS dtlssocket.cpp main.cpp)

add_executable(dtlssocket ${dtlssocket_bin_SRCS})

target_link_qca_libraries(dtlssocket)
target_link_libraries(dtlssocket Qt${QT_MAJOR_VERSION}::Network)
