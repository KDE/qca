ENABLE_TESTING()

set(hashunittest_bin_SRCS hashunittest.cpp)  

add_executable( hashunittest ${hashunittest_bin_SRCS} )

target_compile_definitions(hashunittest PRIVATE TEST_DATA_DIR="${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
target_link_qca_test_libraries(hashunittest)


CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/data/empty ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/data/empty COPYONLY)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/data/twobytes ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/data/twobytes COPYONLY)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/data/twohundredbytes ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/data/twohundredbytes COPYONLY)

add_qca_test(hashunittest "Hashing")
