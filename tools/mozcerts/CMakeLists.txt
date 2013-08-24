project(mozcerts)

set(mozcerts_bin_SRCS main.cpp)  

add_executable(mozcerts ${mozcerts_bin_SRCS})

target_link_libraries( mozcerts ${QCA_LIB_NAME} ${QT_QTGUI_LIBRARY})

