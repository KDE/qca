ENABLE_TESTING()

set(metatype_bin_SRCS metatype.cpp)  

MY_AUTOMOC( metatype_bin_SRCS )

add_executable( metatypeunittest ${metatype_bin_SRCS} )

target_link_qca_test_libraries(metatypeunittest)

add_qca_test(metatypeunittest "MetaTypeUnittest")
