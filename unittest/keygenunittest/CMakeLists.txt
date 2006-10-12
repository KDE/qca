set( keygenunittest_bin_SRCS keygenunittest.cpp)  

MY_AUTOMOC( keygenunittest_bin_SRCS )

add_executable( keygenunittest ${keygenunittest_bin_SRCS} )

target_link_libraries( keygenunittest qca ${QT_QTTEST_LIBRARY})


