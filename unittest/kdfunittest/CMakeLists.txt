set( kdfunittest_bin_SRCS kdfunittest.cpp)  

MY_AUTOMOC( kdfunittest_bin_SRCS )

add_executable( kdfunittest ${kdfunittest_bin_SRCS} )

target_link_libraries( kdfunittest qca ${QT_QTTEST_LIBRARY})

