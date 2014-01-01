ENABLE_TESTING()

set( cipherunittest_bin_SRCS cipherunittest.cpp )

MY_AUTOMOC( cipherunittest_bin_SRCS )

add_executable(cipherunittest ${cipherunittest_bin_SRCS} )

target_link_qca_test_libraries(cipherunittest)

ADD_TEST( SymmetricCipher ${EXECUTABLE_OUTPUT_PATH}/cipherunittest)
