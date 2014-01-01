ENABLE_TESTING()

set( kdfunittest_bin_SRCS kdfunittest.cpp)  

MY_AUTOMOC( kdfunittest_bin_SRCS )

add_executable( kdfunittest ${kdfunittest_bin_SRCS} )

target_link_qca_test_libraries(kdfunittest)

ADD_TEST(KeyDerivationFunction ${EXECUTABLE_OUTPUT_PATH}/kdfunittest)
