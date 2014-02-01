ENABLE_TESTING()

set(bigintunittest_bin_SRCS bigintunittest.cpp)  

MY_AUTOMOC( bigintunittest_bin_SRCS )

add_executable(bigintunittest ${bigintunittest_bin_SRCS} )

target_link_qca_test_libraries(bigintunittest)

add_qca_test(bigintunittest "BigInteger")
