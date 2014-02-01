ENABLE_TESTING()

set(securearrayunittest_bin_SRCS securearrayunittest.cpp)  

MY_AUTOMOC( securearrayunittest_bin_SRCS )

add_executable( securearrayunittest ${securearrayunittest_bin_SRCS} )

target_link_qca_test_libraries(securearrayunittest)

add_qca_test(securearrayunittest "SecureArray")
