ENABLE_TESTING()

set(hexunittest_bin_SRCS hexunittest.cpp)  

MY_AUTOMOC( hexunittest_bin_SRCS )

add_executable( hexunittest ${hexunittest_bin_SRCS} )

target_link_qca_test_libraries(hexunittest)

ADD_TEST(HexadecimalConversion ${EXECUTABLE_OUTPUT_PATH}/hexunittest)
