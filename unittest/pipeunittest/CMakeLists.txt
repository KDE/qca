ENABLE_TESTING()

set(pipeunittest_bin_SRCS pipeunittest.cpp)  

MY_AUTOMOC( pipeunittest_bin_SRCS )

add_executable( pipeunittest ${pipeunittest_bin_SRCS} )

target_link_qca_test_libraries(pipeunittest)

# ADD_TEST(QPipe ${EXECUTABLE_OUTPUT_PATH}/pipeunittest)
