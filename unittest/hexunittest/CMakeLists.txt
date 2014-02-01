ENABLE_TESTING()

set(hexunittest_bin_SRCS hexunittest.cpp)  

MY_AUTOMOC( hexunittest_bin_SRCS )

add_executable( hexunittest ${hexunittest_bin_SRCS} )

target_link_qca_test_libraries(hexunittest)

add_qca_test(hexunittest "HexadecimalConversion")
