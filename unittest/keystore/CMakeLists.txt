ENABLE_TESTING()

set(keystoreunittest_bin_SRCS keystore.cpp)  

MY_AUTOMOC( keystoreunittest_bin_SRCS )

add_executable( keystore ${keystoreunittest_bin_SRCS} )

target_link_qca_test_libraries(keystore)

add_qca_test(keystore "KeyStore")
