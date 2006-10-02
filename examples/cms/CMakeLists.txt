set(cmsexample_bin_SRCS cmsexample.cpp)  

add_executable(cmsexample ${cmsexample_bin_SRCS})

target_link_libraries( cmsexample qca ${QT_QTGUI_LIBRARY})

