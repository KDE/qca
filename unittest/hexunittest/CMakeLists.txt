ENABLE_TESTING()

set(hexunittest_bin_SRCS hexunittest.cpp)  

add_executable( hexunittest ${hexunittest_bin_SRCS} )

target_link_qca_test_libraries(hexunittest)

add_qca_test(hexunittest "HexadecimalConversion")
