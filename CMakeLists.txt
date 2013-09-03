project(QCA)

cmake_minimum_required(VERSION 2.4.5)

option(BUILD_TESTS "Create test" ON)
option(QCA_INSTALL_IN_QT_PREFIX "Install QCA in the Qt prefix instead of the Install prefix" OFF)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules" )

option(QT4_BUILD "Force building with Qt4 even if Qt5 is found")
if (NOT QT4_BUILD)
  find_package(Qt5Core QUIET)
endif()

include(QcaMacro)

if (Qt5Core_FOUND)
  message(STATUS "Building with Qt5 support")
  # Got from ECM
  # Distros have no ECM. So I just copied required cmake modules.
  find_package(Qt5Transitional REQUIRED Core Network)
  include(ECMQt4To5Porting)

  include(GNUInstallDirs)
  setup_qt5_dirs()
  set(LIB_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}")
  set(QCA_LIB_SUFFIX "qt5" CACHE STRING "Qca library suffix")
else()
  set(QT_MIN_VERSION "4.7.0")
  find_package(Qt4 REQUIRED)
  # properly set up compile flags (QT_DEBUG/QT_NO_DEBUG, ...)
  include(${QT_USE_FILE})
  set(QCA_LIB_SUFFIX "" CACHE STRING "Qca library suffix")
  set(LIB_SUFFIX "" CACHE STRING "Define suffix of directory name (32/64)" )
  set(LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}" CACHE PATH "Directory where lib will install")
endif()

set(QCA_LIB_MAJOR_VERSION "2")
set(QCA_LIB_MINOR_VERSION "0")
set(QCA_LIB_PATCH_VERSION "3")

if(QCA_LIB_SUFFIX)
  set(QCA_LIB_NAME qca-${QCA_LIB_SUFFIX})
  set(QCA_MANPAGE_NAME qcatool2-${QCA_LIB_SUFFIX}.1)
else(QCA_LIB_SUFFIX)
  set(QCA_LIB_NAME qca)
  set(QCA_MANPAGE_NAME qcatool2.1)
endif(QCA_LIB_SUFFIX)

set(QCA_LIB_VERSION_STRING "${QCA_LIB_MAJOR_VERSION}.${QCA_LIB_MINOR_VERSION}.${QCA_LIB_PATCH_VERSION}")


if (APPLE)
   find_package(Carbon REQUIRED)
   set(CMAKE_INSTALL_NAME_DIR ${QCA_LIBRARY_INSTALL_DIR})
   set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
endif (APPLE)

# set up RPATH handling, so the libs are found if they are installed to a non-standard location, Alex
if (UNIX  AND NOT  APPLE)
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH  TRUE)
  set(CMAKE_INSTALL_RPATH   "${QCA_LIBRARY_INSTALL_DIR}" )
endif (UNIX  AND NOT  APPLE)


if (WIN32)
 set(CMAKE_DEBUG_POSTFIX "d")
 add_definitions(-DWIN32_LEAN_AND_MEAN)
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

set(QCA_PLUGIN_SUBDIR "${QCA_LIB_NAME}")

if( QCA_INSTALL_IN_QT_PREFIX )
  set(QCA_PREFIX_INSTALL_DIR "${QT_PREFIX_DIR}" CACHE PATH "Directory where qca will install")
  set(QCA_PLUGINS_INSTALL_DIR "${QT_PLUGINS_DIR}/${QCA_PLUGIN_SUBDIR}" CACHE PATH "Directory where qca plugins will install")
  set(QCA_BINARY_INSTALL_DIR "${QT_BINARY_DIR}" CACHE PATH "Directory where qca plugins will install")
  set(QCA_LIBRARY_INSTALL_DIR "${QT_LIBRARY_DIR}" CACHE PATH "Directory where qca library will install")
  set(QCA_FEATURE_INSTALL_DIR "${QT_MKSPECS_DIR}/features" CACHE PATH "Directory where qca feature file will install")
  set(QCA_INCLUDE_INSTALL_DIR "${QT_INCLUDE_DIR}" CACHE PATH "Directory where qca public headers will install")
  set(QCA_PRIVATE_INCLUDE_INSTALL_DIR "${QT_INCLUDE_DIR}" CACHE PATH "Directory where qca headers will install")
  set(QCA_DOC_INSTALL_DIR "${QT_DOC_DIR}/html/qca/" CACHE PATH "Directory where qca documentation will install")
  set(QCA_MAN_INSTALL_DIR "${QT_DATA_DIR}/man" CACHE PATH "Directory where qca man pages will install")
else( QCA_INSTALL_IN_QT_PREFIX )
  set(QCA_PREFIX_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}" CACHE PATH "Directory where qca will install")
  set(QCA_PLUGINS_INSTALL_DIR "${LIB_INSTALL_DIR}/plugins/${QCA_PLUGIN_SUBDIR}" CACHE PATH "Directory where qca plugins will install")
  set(QCA_BINARY_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Directory where qca plugins will install")
  set(QCA_LIBRARY_INSTALL_DIR "${LIB_INSTALL_DIR}" CACHE PATH "Directory where qca library will install")
  set(QCA_FEATURE_INSTALL_DIR "${QT_MKSPECS_DIR}/features" CACHE PATH "Directory where qca feature file will install")
  set(QCA_INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/include/${QCA_LIB_SUFFIX}" CACHE PATH "Directory where qca public headers will install")
  set(QCA_PRIVATE_INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/include/${QCA_LIB_SUFFIX}" CACHE PATH "Directory where qca headers will install")
  set(QCA_DOC_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/share/doc/qca/html" CACHE PATH "Directory where qca documentation will install")
  set(QCA_MAN_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/share/man" CACHE PATH "Directory where qca man pages will install")
endif( QCA_INSTALL_IN_QT_PREFIX )

set(PKGCONFIG_INSTALL_PREFIX "${QCA_LIBRARY_INSTALL_DIR}/pkgconfig" CACHE PATH "Base directory for pkgconfig files")

message(STATUS "QCA prefix is " ${QCA_PREFIX_INSTALL_DIR})
message(STATUS "Plugins will be installed to " ${QCA_PLUGINS_INSTALL_DIR})
message(STATUS "Binary will be installed to " ${QCA_BINARY_INSTALL_DIR})
message(STATUS "Library will be installed to " ${QCA_LIBRARY_INSTALL_DIR})
message(STATUS "Feature file will be installed to " ${QCA_FEATURE_INSTALL_DIR})
message(STATUS "Public headers will be installed to " ${QCA_INCLUDE_INSTALL_DIR})
message(STATUS "Private headers will be installed to " ${QCA_PRIVATE_INCLUDE_INSTALL_DIR})
message(STATUS "Documentation will be installed to " ${QCA_DOC_INSTALL_DIR})
message(STATUS "Man page will be installed to " ${QCA_MAN_INSTALL_DIR})
message(STATUS "Pkg-config file will be installed to " ${PKGCONFIG_INSTALL_PREFIX})

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
      "/etc/ssl/ca-bundle.pem"
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
install(FILES ${public_HEADERS} DESTINATION "${QCA_INCLUDE_INSTALL_DIR}/QtCrypto")

include_directories(${QT_QTCORE_INCLUDE_DIR} "${qca_INCLUDEDIR}/QtCrypto")

if(NOT WIN32)
  if(QCA_LIB_SUFFIX)
    set(QCA_PC_NAME "qca2-${QCA_LIB_SUFFIX}.pc")
  else(QCA_LIB_SUFFIX)
    set(QCA_PC_NAME "qca2.pc")
  endif(QCA_LIB_SUFFIX)

  configure_file("qca2.pc.cmake" "${CMAKE_BINARY_DIR}/${QCA_PC_NAME}" @ONLY)
  install(FILES "${CMAKE_BINARY_DIR}/${QCA_PC_NAME}" DESTINATION ${PKGCONFIG_INSTALL_PREFIX})
endif(NOT WIN32)

configure_file("crypto.prf.cmake" "${CMAKE_BINARY_DIR}/crypto.prf" @ONLY)
install(FILES "${CMAKE_BINARY_DIR}/crypto.prf" DESTINATION "${QCA_FEATURE_INSTALL_DIR}")

configure_file(man/qcatool2.1 "${CMAKE_BINARY_DIR}/${QCA_MANPAGE_NAME}" COPYONLY)
install(FILES "${CMAKE_BINARY_DIR}/${QCA_MANPAGE_NAME}" DESTINATION "${QCA_MAN_INSTALL_DIR}/man1")

add_subdirectory(src)
add_subdirectory(tools)
add_subdirectory(plugins)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(unittest)
  add_subdirectory(examples)
endif(BUILD_TESTS)

