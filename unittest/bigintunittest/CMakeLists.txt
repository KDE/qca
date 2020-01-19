ENABLE_TESTING()

set(bigintunittest_bin_SRCS bigintunittest.cpp)  

add_executable(bigintunittest ${bigintunittest_bin_SRCS} )

target_link_qca_test_libraries(bigintunittest)

add_qca_test(bigintunittest "BigInteger")
