set(cmsexample_bin_SRCS cmsexample.cpp)  

add_executable(cmsexample ${cmsexample_bin_SRCS})

target_link_qca_libraries(cmsexample)
