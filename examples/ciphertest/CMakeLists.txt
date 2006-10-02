set(ciphertest_bin_SRCS ciphertest.cpp)  

add_executable(ciphertest ${ciphertest_bin_SRCS})

target_link_libraries( ciphertest qca ${QT_QTGUI_LIBRARY})

