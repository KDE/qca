set(tlssocket_bin_SRCS tlssocket.cpp main.cpp)  


MY_AUTOMOC( tlssocket_bin_SRCS)

add_executable(tlssocket ${tlssocket_bin_SRCS})

target_link_libraries( tlssocket qca ${QT_QTGUI_LIBRARY} ${QT_QTNETWORK_LIBRARY})

