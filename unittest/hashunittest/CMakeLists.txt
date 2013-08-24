ENABLE_TESTING()

set(hashunittest_bin_SRCS hashunittest.cpp)  

MY_AUTOMOC( hashunittest_bin_SRCS )

add_executable( hashunittest ${hashunittest_bin_SRCS} )

target_link_libraries( hashunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/data/empty ${CMAKE_CURRENT_BINARY_DIR}/data/empty COPYONLY)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/data/twobytes ${CMAKE_CURRENT_BINARY_DIR}/data/twobytes COPYONLY)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/data/twohundredbytes ${CMAKE_CURRENT_BINARY_DIR}/data/twohundredbytes COPYONLY)

ADD_TEST(Hashing ${EXECUTABLE_OUTPUT_PATH}/hashunittest)
