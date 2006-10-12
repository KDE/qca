set(macunittest_bin_SRCS macunittest.cpp)  

MY_AUTOMOC( macunittest_bin_SRCS )

add_executable( macunittest ${macunittest_bin_SRCS} )

target_link_libraries( macunittest qca ${QT_QTTEST_LIBRARY})

