ENABLE_TESTING()

set( keygenunittest_bin_SRCS keygenunittest.cpp)  

MY_AUTOMOC( keygenunittest_bin_SRCS )

add_executable( keygenunittest ${keygenunittest_bin_SRCS} )

target_link_qca_test_libraries(keygenunittest)

ADD_TEST(KeyGeneration ${EXECUTABLE_OUTPUT_PATH}/keygenunittest)
