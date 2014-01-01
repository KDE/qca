ENABLE_TESTING()

set( filewatchunittest_bin_SRCS filewatchunittest.cpp)  

MY_AUTOMOC( filewatchunittest_bin_SRCS )

add_executable( filewatchunittest ${filewatchunittest_bin_SRCS} )

target_link_qca_test_libraries(filewatchunittest)

ADD_TEST(FileWatch ${EXECUTABLE_OUTPUT_PATH}/filewatchunittest)
