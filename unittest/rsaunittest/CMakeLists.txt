ENABLE_TESTING()

set(rsaunittest_bin_SRCS rsaunittest.cpp)  

MY_AUTOMOC( rsaunittest_bin_SRCS )

add_executable(rsaunittest ${rsaunittest_bin_SRCS} )

target_link_qca_test_libraries(rsaunittest)

add_qca_test(rsaunittest "RSA")
