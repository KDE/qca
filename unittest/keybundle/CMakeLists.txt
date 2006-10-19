set(keybundleunittest_bin_SRCS keybundle.cpp)  

MY_AUTOMOC( keybundleunittest_bin_SRCS )

add_executable( keybundle ${keybundleunittest_bin_SRCS} )

target_link_libraries( keybundle qca ${QT_QTTEST_LIBRARY})


