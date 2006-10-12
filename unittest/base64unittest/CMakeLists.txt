set(base64unittest_bin_SRCS base64unittest.cpp)  

MY_AUTOMOC( base64unittest_bin_SRCS )

add_executable(base64unittest ${base64unittest_bin_SRCS} )

target_link_libraries( base64unittest qca ${QT_QTTEST_LIBRARY})

