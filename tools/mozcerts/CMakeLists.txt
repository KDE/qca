project(mozcerts)

set(mozcerts_bin_SRCS main.cpp)  

add_executable(mozcerts ${mozcerts_bin_SRCS})

target_link_libraries( mozcerts qca ${QT_QTGUI_LIBRARY})

