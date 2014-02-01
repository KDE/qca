ENABLE_TESTING()

set(base64unittest_bin_SRCS base64unittest.cpp)  

MY_AUTOMOC( base64unittest_bin_SRCS )

add_executable(base64unittest ${base64unittest_bin_SRCS} )

target_link_qca_test_libraries(base64unittest)

add_qca_test(base64unittest "Base64")
