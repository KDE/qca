ENABLE_TESTING()

set( dsaunittest_bin_SRCS dsaunittest.cpp)  

MY_AUTOMOC( dsaunittest_bin_SRCS )

add_executable( dsaunittest ${dsaunittest_bin_SRCS} )

target_link_qca_test_libraries(dsaunittest)

add_qca_test(dsaunittest "DigitalSignatureAlgorithm")
