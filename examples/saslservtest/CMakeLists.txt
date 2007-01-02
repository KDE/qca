set(saslservtest_bin_SRCS saslservtest.cpp)  

MY_AUTOMOC( saslservtest_bin_SRCS)

add_executable(saslservtest ${saslservtest_bin_SRCS})

target_link_libraries( saslservtest qca ${QT_QTGUI_LIBRARY} ${QT_QTNETWORK_LIBRARY})
