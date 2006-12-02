ENABLE_TESTING()

set(keystoreunittest_bin_SRCS keystore.cpp)  

MY_AUTOMOC( keystoreunittest_bin_SRCS )

add_executable( keystore ${keystoreunittest_bin_SRCS} )

target_link_libraries( keystore qca ${QT_QTTEST_LIBRARY})

ADD_TEST(KeyStore ${EXECUTABLE_OUTPUT_PATH}/keystore)
