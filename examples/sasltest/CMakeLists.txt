set(sasltest_bin_SRCS sasltest.cpp)  

MY_AUTOMOC( sasltest_bin_SRCS)

add_executable(sasltest ${sasltest_bin_SRCS})

target_link_libraries( sasltest qca ${QT_QTGUI_LIBRARY} ${QT_QTNETWORK_LIBRARY})
