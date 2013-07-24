set(tlssocket_bin_moc_SRCS tlssocket.cpp)
set(tlssocket_bin_nonmoc_SRCS  main.cpp)


MY_AUTOMOC( tlssocket_bin_moc_SRCS)

add_executable(tlssocket ${tlssocket_bin_moc_SRCS} ${tlssocket_bin_nonmoc_SRCS})

target_link_libraries( tlssocket qca ${QT_QTGUI_LIBRARY} ${QT_QTNETWORK_LIBRARY})

