set(providertest_bin_SRCS providertest.cpp)  

add_executable(providertest ${providertest_bin_SRCS})

target_link_libraries( providertest ${QCA_LIB_NAME} ${QT_QTGUI_LIBRARY})

