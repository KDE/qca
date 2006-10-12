set(keylengthunittest_bin_SRCS keylengthunittest.cpp)  

MY_AUTOMOC( keylengthunittest_bin_SRCS )

add_executable( keylengthunittest ${keylengthunittest_bin_SRCS} )

target_link_libraries( keylengthunittest qca ${QT_QTTEST_LIBRARY})


