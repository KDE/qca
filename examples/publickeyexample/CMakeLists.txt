set(publickeyexample_bin_SRCS publickeyexample.cpp)  

add_executable(publickeyexample ${publickeyexample_bin_SRCS})

target_link_qca_libraries(publickeyexample)
