ENABLE_TESTING()

set(pipeunittest_bin_SRCS pipeunittest.cpp)  

add_executable( pipeunittest ${pipeunittest_bin_SRCS} )

target_link_qca_test_libraries(pipeunittest)

# add_qca_test(pipeunittest "QPipe")
