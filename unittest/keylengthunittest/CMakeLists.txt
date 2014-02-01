ENABLE_TESTING()

set(keylengthunittest_bin_SRCS keylengthunittest.cpp)  

MY_AUTOMOC( keylengthunittest_bin_SRCS )

add_executable( keylengthunittest ${keylengthunittest_bin_SRCS} )

target_link_qca_test_libraries(keylengthunittest)

add_qca_test(keylengthunittest "KeyLength")
