set(tlsunittest_bin_SRCS tlsunittest.cpp)  

MY_AUTOMOC( tlsunittest_bin_SRCS )

add_executable(tlsunittest ${tlsunittest_bin_SRCS} )

target_link_libraries( tlsunittest qca ${QT_QTTEST_LIBRARY})

