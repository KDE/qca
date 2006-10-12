set( dsaunittest_bin_SRCS dsaunittest.cpp)  

MY_AUTOMOC( dsaunittest_bin_SRCS )

add_executable( dsaunittest ${dsaunittest_bin_SRCS} )

target_link_libraries( dsaunittest qca ${QT_QTTEST_LIBRARY})


