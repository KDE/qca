set(staticunittest_bin_SRCS staticunittest.cpp)  

MY_AUTOMOC( staticunittest_bin_SRCS )

add_executable( staticunittest ${staticunittest_bin_SRCS} )

target_link_libraries( staticunittest qca ${QT_QTTEST_LIBRARY})


