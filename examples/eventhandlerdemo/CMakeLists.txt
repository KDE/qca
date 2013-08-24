set(eventhandlerdemo_bin_SRCS eventhandlerdemo.cpp)  

MY_AUTOMOC( eventhandlerdemo_bin_SRCS)

add_executable(eventhandlerdemo ${eventhandlerdemo_bin_SRCS})

target_link_libraries( eventhandlerdemo ${QCA_LIB_NAME} ${QT_QTCORE_LIBRARY})

