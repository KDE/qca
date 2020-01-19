ENABLE_TESTING()

set(staticunittest_bin_SRCS staticunittest.cpp)  

add_executable( staticunittest ${staticunittest_bin_SRCS} )

target_link_qca_test_libraries(staticunittest)

add_qca_test(staticunittest "StaticFunctions")
