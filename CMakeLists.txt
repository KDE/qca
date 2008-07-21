project(QCA)

cmake_minimum_required(VERSION 2.4.5)

option(BUILD_TESTS "Create test" ON)

set(LIB_SUFFIX "" CACHE STRING "Define suffix of directory name (32/64)" )

set(LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}" CACHE STRING "Directory where lib will install")

set(PKGCONFIG_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/pkgconfig/" CACHE STRING "Base directory for pkgconfig files")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules" )

find_package(Qt4 REQUIRED)

set(QCA_LIB_MAJOR_VERSION "2")
set(QCA_LIB_MINOR_VERSION "0")
set(QCA_LIB_PATCH_VERSION "1")

set(QCA_LIB_VERSION_STRING "${QCA_LIB_MAJOR_VERSION}.${QCA_LIB_MINOR_VERSION}.${QCA_LIB_PATCH_VERSION}")


if (APPLE)
   find_package(Carbon REQUIRED)
   set(CMAKE_INSTALL_NAME_DIR ${LIB_INSTALL_DIR})
   set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
endif (APPLE)

# set up RPATH handling, so the libs are found if they are installed to a non-standard location, Alex
if (UNIX  AND NOT  APPLE)
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH  TRUE)
  set(CMAKE_INSTALL_RPATH   "${LIB_INSTALL_DIR}" )
endif (UNIX  AND NOT  APPLE)


if (WIN32)
 set(CMAKE_DEBUG_POSTFIX "d")
endif (WIN32)

if (CMAKE_COMPILER_IS_GNUCXX)
   if (CMAKE_SYSTEM_NAME MATCHES Linux)
     add_definitions (-D_BSD_SOURCE)
     set ( CMAKE_C_FLAGS     "${CMAKE_C_FLAGS} -Wno-long-long -ansi -Wundef -Wcast-align -Werror-implicit-function-declaration -Wchar-subscripts -Wall -W -Wpointer-arith -Wwrite-strings -Wformat-security -Wmissing-format-attribute -fno-common")
     set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wnon-virtual-dtor -Wno-long-long -ansi -Wundef -Wcast-align -Wchar-subscripts -Wall -W -Wpointer-arith -Wwrite-strings -Wformat-security -fno-check-new -fno-common")
   endif (CMAKE_SYSTEM_NAME MATCHES Linux)
endif (CMAKE_COMPILER_IS_GNUCXX)

add_definitions (${QT_DEFINITIONS})
include_directories(include/QtCrypto/ ${QT_INCLUDES})

# Always include srcdir and builddir in include path
# This saves typing ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY} in about every subdir
set(CMAKE_INCLUDE_CURRENT_DIR ON)

# put the include dirs which are in the source or build tree
# before all other include dirs, so the headers in the sources
# are prefered over the already installed ones
set(CMAKE_INCLUDE_DIRECTORIES_PROJECT_BEFORE ON)

set(qca_INCLUDEDIR "${CMAKE_CURRENT_SOURCE_DIR}/include" )
set(LIBRARY_OUTPUT_PATH "${CMAKE_BINARY_DIR}/lib${LIB_SUFFIX}" )

set(qca_PLUGINSDIR "${QT_PLUGINS_DIR}/crypto/")
message(STATUS "Plugins will be installed to " ${qca_PLUGINSDIR})

include(QcaMacro)

message(STATUS "Checking for certstore..")
# fixme add OR mac
if( WIN32 )
# USE BUILTIN
else ( WIN32 )
  if ( ENV{QC_CERTSTORE_PATH} )
    if(EXISTS ENV{QC_CERTSTORE_PATH})
      set( qca_CERTSTORE $ENV{QC_CERTSTORE_PATH})
    else(EXISTS ENV{QC_CERTSTORE_PATH})
      # path to try
    endif(EXISTS ENV{QC_CERTSTORE_PATH})
  else( ENV{QC_CERTSTORE_PATH} )
    set( toTry
      "/etc/ssl/certs/ca-certificates.crt"
      "/usr/share/ssl/cert.pem"
      "/usr/share/ssl/certs/ca-bundle.crt"
      "/etc/pki/tls/cert.pem"
      "/usr/share/curl/curl-ca-bundle.crt"
    )
    foreach (_current_try ${toTry})
      if(EXISTS ${_current_try})
        set( qca_CERTSTORE ${_current_try})
      endif(EXISTS ${_current_try})
    endforeach (_current_try)
  endif( ENV{QC_CERTSTORE_PATH} )
endif(WIN32)

if (qca_CERTSTORE)
  message(STATUS "Found system certstore")
else (qca_CERTSTORE)
  message(STATUS "Using built in certstore.")
  set( qca_CERTSTORE "${CMAKE_CURRENT_SOURCE_DIR}/certs/rootcerts.pem")
  # note that INSTALL_FILES targets are relative to the current installation prefix...
  install_files( "/certs" FILES "${CMAKE_CURRENT_SOURCE_DIR}/certs/rootcerts.pem" )
endif (qca_CERTSTORE)
message(STATUS "certstore path: " ${qca_CERTSTORE})
add_definitions( -DQCA_SYSTEMSTORE_PATH="\\\"${qca_CERTSTORE}\\\"" )


set( private_HEADERS ${qca_INCLUDEDIR}/QtCrypto/qca_plugin.h ${qca_INCLUDEDIR}/QtCrypto/qca_systemstore.h )

set( public_HEADERS 
  ${qca_INCLUDEDIR}/QtCrypto/qca.h
  ${qca_INCLUDEDIR}/QtCrypto/qcaprovider.h
  ${qca_INCLUDEDIR}/QtCrypto/QtCrypto
  ${qca_INCLUDEDIR}/QtCrypto/qca_export.h
  ${qca_INCLUDEDIR}/QtCrypto/qca_support.h
  ${qca_INCLUDEDIR}/QtCrypto/qca_tools.h
  ${qca_INCLUDEDIR}/QtCrypto/qca_core.h
  ${qca_INCLUDEDIR}/QtCrypto/qca_textfilter.h
  ${qca_INCLUDEDIR}/QtCrypto/qca_basic.h
  ${qca_INCLUDEDIR}/QtCrypto/qca_publickey.h
  ${qca_INCLUDEDIR}/QtCrypto/qca_cert.h
  ${qca_INCLUDEDIR}/QtCrypto/qca_keystore.h
  ${qca_INCLUDEDIR}/QtCrypto/qca_securelayer.h
  ${qca_INCLUDEDIR}/QtCrypto/qca_securemessage.h
  ${qca_INCLUDEDIR}/QtCrypto/qpipe.h )

set( qca_HEADERS ${private_HEADERS} ${public_HEADERS} )

#install public headers only
install(FILES ${public_HEADERS} DESTINATION "${CMAKE_INSTALL_PREFIX}/include/QtCrypto")

include_directories(${QT_QTCORE_INCLUDE_DIR} "${qca_INCLUDEDIR}/QtCrypto")

if(NOT WIN32)
  configure_file("qca2.pc.cmake" "${CMAKE_BINARY_DIR}/qca2.pc" @ONLY)
  install(FILES "${CMAKE_BINARY_DIR}/qca2.pc" DESTINATION ${PKGCONFIG_INSTALL_PREFIX})
endif(NOT WIN32)

configure_file("crypto.prf.cmake" "${CMAKE_BINARY_DIR}/crypto.prf" @ONLY)
install(FILES "${CMAKE_BINARY_DIR}/crypto.prf" DESTINATION ${CMAKE_INSTALL_PREFIX}/mkspecs/features)

install(FILES man/qcatool2.1 DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man1)

add_subdirectory(src)
add_subdirectory(tools)
add_subdirectory(plugins)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(unittest)
  add_subdirectory(examples)
endif(BUILD_TESTS)

