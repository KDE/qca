set(providertest_bin_SRCS providertest.cpp)  

add_executable(providertest ${providertest_bin_SRCS})

target_link_qca_libraries(providertest)
