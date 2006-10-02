set(publickeyexample_bin_SRCS publickeyexample.cpp)  

add_executable(publickeyexample ${publickeyexample_bin_SRCS})

target_link_libraries( publickeyexample qca ${QT_QTGUI_LIBRARY})

