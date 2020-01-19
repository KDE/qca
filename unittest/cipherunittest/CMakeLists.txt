enable_testing()

set(cipherunittest_bin_HDRS cipherunittest.h)
set(cipherunittest_bin_SRCS cipherunittest.cpp)

add_executable(cipherunittest ${cipherunittest_bin_SRCS} ${EXTRA_SRCS} ${cipherunittest_bin_HDRS})

target_link_qca_test_libraries(cipherunittest)

add_qca_test(cipherunittest "SymmetricCipher")
