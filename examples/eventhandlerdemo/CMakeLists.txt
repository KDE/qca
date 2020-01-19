set(eventhandlerdemo_bin_SRCS eventhandlerdemo.cpp)  

add_executable(eventhandlerdemo ${eventhandlerdemo_bin_SRCS})

target_link_qca_libraries(eventhandlerdemo)
