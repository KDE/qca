set(sasltest_bin_SRCS sasltest.cpp)  

add_executable(sasltest ${sasltest_bin_SRCS})

target_link_libraries( sasltest qca ${QT_QTGUI_LIBRARY})

