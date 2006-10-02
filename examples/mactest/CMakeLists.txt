set(mactest_bin_SRCS mactest.cpp)  

add_executable(mactest ${mactest_bin_SRCS})

target_link_libraries( mactest qca ${QT_QTGUI_LIBRARY})

