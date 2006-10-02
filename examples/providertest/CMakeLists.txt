set(providertest_bin_SRCS providertest.cpp)  

add_executable(providertest ${providertest_bin_SRCS})

target_link_libraries( providertest qca ${QT_QTGUI_LIBRARY})

