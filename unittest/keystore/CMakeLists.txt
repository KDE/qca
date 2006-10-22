set(keystoreunittest_bin_SRCS keystore.cpp)  

MY_AUTOMOC( keystoreunittest_bin_SRCS )

add_executable( keystore ${keystoreunittest_bin_SRCS} )

target_link_libraries( keystore qca ${QT_QTTEST_LIBRARY})


