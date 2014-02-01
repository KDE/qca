ENABLE_TESTING()

set(macunittest_bin_SRCS macunittest.cpp)  

MY_AUTOMOC( macunittest_bin_SRCS )

add_executable( macunittest ${macunittest_bin_SRCS} )

target_link_qca_test_libraries(macunittest)

add_qca_test(macunittest "MessageAuthenticationCode")
