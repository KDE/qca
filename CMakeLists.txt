# Checking for user explicity defined CMAKE_INSTALL_PREFIX
# It must be done before project(...)
if(NOT CMAKE_INSTALL_PREFIX)
  set(QCA_INSTALL_IN_QT_PREFIX ON)
  # If CMAKE_INSTALL_PREFIX is set in cmake arguments
  unset(CMAKE_INSTALL_PREFIX CACHE)
endif(NOT CMAKE_INSTALL_PREFIX)

project(qca)

cmake_minimum_required(VERSION 2.6.0)

set(QCA_LIB_MAJOR_VERSION "2")
set(QCA_LIB_MINOR_VERSION "1")
set(QCA_LIB_PATCH_VERSION "0")

# Do not automatically link Qt executables to qtmain target on Windows.
# QCA exucatables use console mode only. Not need to link against
# qtmain.lib.
cmake_policy(SET CMP0020 OLD)

option(BUILD_TESTS "Create test" ON)
option(BUILD_TOOLS "Compile mozcerts and qcatool" ON)
set(BUILD_PLUGINS "auto" CACHE STRING "Plugins for building (also possible values: none, all and auto)")
option(BUILD_SHARED_LIBS "Build shared library" ON)
option(DEVELOPER_MODE "Special developer mode" OFF)

if(APPLE)
  option(OSX_FRAMEWORK "Build a Mac OS X Framework" ON)
else()
  set(OSX_FRAMEWORK OFF)
endif()

find_package(Doxygen)

string(TOLOWER "${BUILD_PLUGINS}" BUILD_PLUGINS)
if(NOT BUILD_PLUGINS)
  set(BUILD_PLUGINS "none")
endif(NOT BUILD_PLUGINS)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules" )

option(QT4_BUILD "Force building with Qt4 even if Qt5 is found")
if (NOT QT4_BUILD)
  find_package(Qt5Core QUIET)
  mark_as_advanced(Qt5Core_DIR)
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
  set(QCA_QT_PC_VERSION "Qt5Core")
else()
  set(QT_MIN_VERSION "4.7.0")
  set(QT_USE_IMPORTED_TARGETS ON)
  if(BUILD_TESTS)
    find_package(Qt4 REQUIRED QtCore QtNetwork QtTest)
  else(BUILD_TESTS)
    find_package(Qt4 REQUIRED QtCore)
  endif(BUILD_TESTS)
  # WORKAROUND: Seems it must be done in Qt4 find module but didn't
  mark_as_advanced(QT_QMAKE_EXECUTABLE)

  # properly set up compile flags (QT_DEBUG/QT_NO_DEBUG, ...)
  include(${QT_USE_FILE})
  setup_qt4_dirs()
  set(QCA_QT_PC_VERSION "QtCore")
endif()

# QCA can be shared but plugins will be static
# if Qt is static.
if(NOT BUILD_SHARED_LIBS OR QT_IS_STATIC)
  set(STATIC_PLUGINS ON)
  add_definitions(-DQT_STATICPLUGIN)
  set(PLUGIN_TYPE "STATIC")
else(NOT BUILD_SHARED_LIBS OR QT_IS_STATIC)
  set(PLUGIN_TYPE "MODULE")
endif(NOT BUILD_SHARED_LIBS OR QT_IS_STATIC)

set(QCA_SUFFIX "" CACHE STRING "QCA common suffix")
if(QCA_SUFFIX)
  set(QCA_LIB_NAME qca-${QCA_SUFFIX})
  set(QCA_TOOL_NAME qcatool-${QCA_SUFFIX})
  set(MOZCERTS_NAME mozcerts-${QCA_SUFFIX})
  set(QCA_PC_NAME qca2-${QCA_SUFFIX}.pc)
else(QCA_SUFFIX)
  set(QCA_LIB_NAME qca)
  set(QCA_TOOL_NAME qcatool)
  set(MOZCERTS_NAME mozcerts)
  set(QCA_PC_NAME qca2.pc)
endif(QCA_SUFFIX)

set(QCA_LIB_VERSION_STRING "${QCA_LIB_MAJOR_VERSION}.${QCA_LIB_MINOR_VERSION}.${QCA_LIB_PATCH_VERSION}")

configure_file("include/QtCrypto/qca_version.h.in" "${CMAKE_BINARY_DIR}/qca_version.h")

if (WIN32)
 set(CMAKE_DEBUG_POSTFIX "d")
 add_definitions(-DWIN32_LEAN_AND_MEAN)
elseif (APPLE)
 set(CMAKE_DEBUG_POSTFIX "_debug")
endif (WIN32)

if (CMAKE_COMPILER_IS_GNUCXX)
   if (CMAKE_SYSTEM_NAME MATCHES Linux)
     add_definitions (-D_BSD_SOURCE)
     set ( CMAKE_C_FLAGS     "${CMAKE_C_FLAGS} -Wno-long-long -ansi -Wundef -Wcast-align -Werror-implicit-function-declaration -Wchar-subscripts -Wall -W -Wpointer-arith -Wwrite-strings -Wformat-security -Wmissing-format-attribute -fno-common")
     set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wnon-virtual-dtor -Wno-long-long -ansi -Wundef -Wcast-align -Wchar-subscripts -Wall -W -Wpointer-arith -Wwrite-strings -Wformat-security -fno-check-new -fno-common")
   endif (CMAKE_SYSTEM_NAME MATCHES Linux)
endif (CMAKE_COMPILER_IS_GNUCXX)

add_definitions (${QT_DEFINITIONS})
include_directories("include/QtCrypto/")
# for generated files
include_directories(${CMAKE_BINARY_DIR})

if(NOT DEVELOPER_MODE)
  # uninstall target
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()

# Always include srcdir and builddir in include path
# This saves typing ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY} in about every subdir
set(CMAKE_INCLUDE_CURRENT_DIR ON)

# put the include dirs which are in the source or build tree
# before all other include dirs, so the headers in the sources
# are prefered over the already installed ones
set(CMAKE_INCLUDE_DIRECTORIES_PROJECT_BEFORE ON)

set(qca_INCLUDEDIR "${CMAKE_CURRENT_SOURCE_DIR}/include" )

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin" )
# Use the same path for shared and static library
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib" )
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib" )

if( QCA_INSTALL_IN_QT_PREFIX )
  set(QCA_PREFIX_INSTALL_DIR "${QT_PREFIX_DIR}" CACHE PATH "Directory where qca will install")
  set(QCA_PLUGINS_INSTALL_DIR "${QT_PLUGINS_DIR}" CACHE PATH "Directory where qca plugins will install")
  set(QCA_BINARY_INSTALL_DIR "${QT_BINARY_DIR}" CACHE PATH "Directory where qca plugins will install")
  set(QCA_LIBRARY_INSTALL_DIR "${QT_LIBRARY_DIR}" CACHE PATH "Directory where qca library will install")
  set(QCA_FEATURE_INSTALL_DIR "${QT_MKSPECS_DIR}/features" CACHE PATH "Directory where qca feature file will install")
  set(QCA_INCLUDE_INSTALL_DIR "${QT_HEADERS_DIR}" CACHE PATH "Directory where qca public headers will install")
  set(QCA_PRIVATE_INCLUDE_INSTALL_DIR "${QT_HEADERS_DIR}" CACHE PATH "Directory where qca headers will install")
  set(QCA_DOC_INSTALL_DIR "${QT_DOC_DIR}/html/qca/" CACHE PATH "Directory where qca documentation will install")
  set(QCA_MAN_INSTALL_DIR "${QT_DATA_DIR}/man" CACHE PATH "Directory where qca man pages will install")
else( QCA_INSTALL_IN_QT_PREFIX )
  # Cmake says nothing about LIB_SUFFIX
  # de facto it is a standard way to specify lib suffix on many distros
  set(LIB_SUFFIX "" CACHE STRING "Define suffix of directory name (32/64)" )
  set(LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}" CACHE PATH "Directory where lib will install")

  set(QCA_PREFIX_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}" CACHE PATH "Directory where qca will install")
  set(QCA_PLUGINS_INSTALL_DIR "${LIB_INSTALL_DIR}/${QCA_LIB_NAME}" CACHE PATH "Directory where qca plugins will install")
  set(QCA_BINARY_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Directory where qca plugins will install")
  set(QCA_LIBRARY_INSTALL_DIR "${LIB_INSTALL_DIR}" CACHE PATH "Directory where qca library will install")
  set(QCA_FEATURE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/mkspecs/features" CACHE PATH "Directory where qca feature file will install")
  set(QCA_INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Directory where qca public headers will install")
  set(QCA_PRIVATE_INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Directory where qca headers will install")
  set(QCA_DOC_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/share/doc/${QCA_LIB_NAME}/html" CACHE PATH "Directory where qca documentation will install")
  set(QCA_MAN_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/share/man" CACHE PATH "Directory where qca man pages will install")
endif( QCA_INSTALL_IN_QT_PREFIX )

set(PKGCONFIG_INSTALL_PREFIX "${QCA_LIBRARY_INSTALL_DIR}/pkgconfig" CACHE PATH "Base directory for pkgconfig files")

normalize_path(QCA_PREFIX_INSTALL_DIR)

# check for oportunity to use relative paths
option(USE_RELATIVE_PATHS "Try to make relocatable package")

foreach(PATH QCA_PLUGINS_INSTALL_DIR
             QCA_BINARY_INSTALL_DIR
             QCA_LIBRARY_INSTALL_DIR
             QCA_FEATURE_INSTALL_DIR
             QCA_INCLUDE_INSTALL_DIR
             QCA_PRIVATE_INCLUDE_INSTALL_DIR
             QCA_DOC_INSTALL_DIR
             QCA_MAN_INSTALL_DIR
             PKGCONFIG_INSTALL_PREFIX)

  # Normalize path before comparsion
  normalize_path(${PATH})

  # if all paths are subdirs of CMAKE_INSTALL_PREFIX it is possible to use relative paths
  string(FIND "${${PATH}}" "${QCA_PREFIX_INSTALL_DIR}/" POS)
  if(NOT "${POS}" STREQUAL "0")
    set(USE_RELATIVE_PATHS OFF)
  endif()
endforeach()

if(NOT WIN32)
  if(OSX_FRAMEWORK)
    set(PKGCONFIG_CFLAGS "-F\${libdir} -I\${libdir}/${QCA_LIB_NAME}.framework/Headers")
    set(PKGCONFIG_LIBS "-F\${libdir} -framework ${QCA_LIB_NAME}")
  else()
    set(PKGCONFIG_CFLAGS "-I\${includedir}")
    set(PKGCONFIG_LIBS "-L\${libdir} -l${QCA_LIB_NAME}")
  endif()

  # qca2.pc uses absolute paths. So it must be there. Don't rellocate this.
  configure_file("qca2.pc.cmake" "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/pkgconfig/${QCA_PC_NAME}" @ONLY)
  if(NOT DEVELOPER_MODE)
    install(FILES "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/pkgconfig/${QCA_PC_NAME}" DESTINATION ${PKGCONFIG_INSTALL_PREFIX})
  endif()
endif(NOT WIN32)

# strip CMAKE_INSTALL_PREFIX in all paths
if(USE_RELATIVE_PATHS)
  message(STATUS "Installed package is relocatable")
  file(RELATIVE_PATH CRYPTO_PRF_RELATIVE_PATH "${QCA_FEATURE_INSTALL_DIR}" ${CMAKE_INSTALL_PREFIX})
  set(CRYPTO_PRF_RELATIVE_PATH "$$PWD/${CRYPTO_PRF_RELATIVE_PATH}")
  foreach(PATH QCA_PLUGINS_INSTALL_DIR
               QCA_BINARY_INSTALL_DIR
               QCA_LIBRARY_INSTALL_DIR
               QCA_FEATURE_INSTALL_DIR
               QCA_INCLUDE_INSTALL_DIR
               QCA_PRIVATE_INCLUDE_INSTALL_DIR
               QCA_DOC_INSTALL_DIR
               QCA_MAN_INSTALL_DIR
               PKGCONFIG_INSTALL_PREFIX)

     file(RELATIVE_PATH ${PATH} ${CMAKE_INSTALL_PREFIX} "${${PATH}}")
  endforeach()
else()
  message(STATUS "Installed package is NOT relocatable")
  set(CRYPTO_PRF_RELATIVE_PATH "")
endif()

if(DEVELOPER_MODE)
  add_definitions(-DDEVELOPER_MODE)

# To prefer plugins from build tree when run qca from build tree
  file(WRITE ${CMAKE_BINARY_DIR}/bin/qt.conf
"[Paths]
Plugins=${CMAKE_BINARY_DIR}/lib/${QCA_LIB_NAME}
")
endif()

if (APPLE)
   find_package(Carbon REQUIRED)
   set(CMAKE_INSTALL_NAME_DIR ${QCA_LIBRARY_INSTALL_DIR})
   set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
endif (APPLE)

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
  if(NOT DEVELOPER_MODE)
    install(FILES "${qca_CERTSTORE}" DESTINATION "${QCA_PREFIX_INSTALL_DIR}/certs")
  endif()
endif (qca_CERTSTORE)
message(STATUS "certstore path: " ${qca_CERTSTORE})
add_definitions( -DQCA_SYSTEMSTORE_PATH="${qca_CERTSTORE}" )


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
  ${CMAKE_BINARY_DIR}/qca_version.h
  ${qca_INCLUDEDIR}/QtCrypto/qpipe.h
  ${qca_INCLUDEDIR}/QtCrypto/qca_safetimer.h)

set( qca_HEADERS ${private_HEADERS} ${public_HEADERS} )

include_directories(${QT_QTCORE_INCLUDE_DIR} "${qca_INCLUDEDIR}/QtCrypto")

configure_file("crypto.prf.cmake" "${CMAKE_BINARY_DIR}/mkspecs/features/crypto.prf" @ONLY)
if(NOT DEVELOPER_MODE)
  install(FILES "${CMAKE_BINARY_DIR}/mkspecs/features/crypto.prf" DESTINATION "${QCA_FEATURE_INSTALL_DIR}")
endif()

configure_file(man/qcatool.1 "${CMAKE_BINARY_DIR}/share/man/man1/${QCA_TOOL_NAME}.1" COPYONLY)
if(NOT DEVELOPER_MODE)
  install(FILES "${CMAKE_BINARY_DIR}/share/man/man1/${QCA_TOOL_NAME}.1" DESTINATION "${QCA_MAN_INSTALL_DIR}/man1")
endif()

set(QCA_CRYPTO_INSTALL_DIR "${QCA_PLUGINS_INSTALL_DIR}/crypto")

add_subdirectory(src)
add_subdirectory(plugins)

if(STATIC_PLUGINS)
  # Generate header with static plugins list
  file(WRITE "${CMAKE_BINARY_DIR}/import_plugins.h" "#include <QtPlugin>\n")
  foreach(PLUGIN IN LISTS PLUGINS)
    if(WITH_${PLUGIN}_PLUGIN_INTERNAL)
      string(REPLACE "-" "_" IMPORT_NAME "qca-${PLUGIN}")
      file(APPEND "${CMAKE_BINARY_DIR}/import_plugins.h" "Q_IMPORT_PLUGIN(${IMPORT_NAME})\n")
    endif(WITH_${PLUGIN}_PLUGIN_INTERNAL)
  endforeach(PLUGIN IN LISTS PLUGINS)
endif(STATIC_PLUGINS)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(unittest)
  add_subdirectory(examples)
endif(BUILD_TESTS)
if(BUILD_TOOLS)
  add_subdirectory(tools)
endif(BUILD_TOOLS)

if(DOXYGEN_FOUND)
  configure_file(${CMAKE_SOURCE_DIR}/Doxyfile.in ${CMAKE_BINARY_DIR}/Doxyfile @ONLY)
  add_custom_target(doc
    ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/Doxyfile
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/images
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/images/qca-arch.eps ${CMAKE_BINARY_DIR}/images/qca-arch.eps
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/images/qca-arch.png ${CMAKE_BINARY_DIR}/images/qca-arch.png
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Generating API documentation with Doxygen" VERBATIM)
endif(DOXYGEN_FOUND)

include(CMakePackageConfigHelpers)
configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/QcaConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/Qca/QcaConfig.cmake"
  INSTALL_DESTINATION ${QCA_LIBRARY_INSTALL_DIR}/cmake/Qca
)
write_basic_config_version_file("${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/Qca/QcaConfigVersion.cmake" VERSION ${QCA_LIB_VERSION_STRING} COMPATIBILITY AnyNewerVersion)

if(NOT DEVELOPER_MODE)

  # /usr/local is traditional path for installing apps on POSIX-systems.
  # I consciously break this. Qt by default looks plugins and features only in
  # own directory. So by default install libs in Qt prefix it is a best choice.
  # This can be unwanted behaviour for users who don't read INSTALL file or/and
  # not read cmake reports. I just try to warn their.

  # In really anybody who do cmake . && make && sudo make install do it for own risk.

  if(QCA_INSTALL_IN_QT_PREFIX)
    string(ASCII 27 ESCAPE)
    message("")
    message("${ESCAPE}[31m")
    message("!!!!!!!!!!!!!!!!!!!!!ATTENTION!!!!!!!!!!!!!!!!!!!!!!")
    message("!! QCA will be installed in Qt prefix             !!")
    message("!! If you want to install in /usr/local           !!")
    message("!! you MUST explicity define CMAKE_INSTALL_PREFIX !!")
    message("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    message("${ESCAPE}[0m")
  endif(QCA_INSTALL_IN_QT_PREFIX)

  message("")
  if(USE_RELATIVE_PATHS)
    message("QCA prefix is " "${QCA_PREFIX_INSTALL_DIR}")
    message("Plugins will be installed to " "${QCA_PREFIX_INSTALL_DIR}/${QCA_PLUGINS_INSTALL_DIR}")
    message("Binary will be installed to " "${QCA_PREFIX_INSTALL_DIR}/${QCA_BINARY_INSTALL_DIR}")
    if(OSX_FRAMEWORK)
      message("Framework will be installed to " "${QCA_PREFIX_INSTALL_DIR}/${QCA_LIBRARY_INSTALL_DIR}")
    else()
      message("Library will be installed to " "${QCA_PREFIX_INSTALL_DIR}/${QCA_LIBRARY_INSTALL_DIR}")
      message("Public headers will be installed to " "${QCA_PREFIX_INSTALL_DIR}/${QCA_INCLUDE_INSTALL_DIR}")
      message("Private headers will be installed to " "${QCA_PREFIX_INSTALL_DIR}/${QCA_PRIVATE_INCLUDE_INSTALL_DIR}")
    endif()
    message("Feature file will be installed to " "${QCA_PREFIX_INSTALL_DIR}/${QCA_FEATURE_INSTALL_DIR}")
    message("Documentation will be installed to " "${QCA_PREFIX_INSTALL_DIR}/${QCA_DOC_INSTALL_DIR}")
    message("Man page will be installed to " "${QCA_PREFIX_INSTALL_DIR}/${QCA_MAN_INSTALL_DIR}")
    message("Pkg-config file will be installed to " "${QCA_PREFIX_INSTALL_DIR}/${PKGCONFIG_INSTALL_PREFIX}")
  else()
    message("QCA prefix is " "${QCA_PREFIX_INSTALL_DIR}")
    message("Plugins will be installed to " "${QCA_PLUGINS_INSTALL_DIR}")
    message("Binary will be installed to " "${QCA_BINARY_INSTALL_DIR}")
    if(OSX_FRAMEWORK)
      message("Framework will be installed to " "${QCA_LIBRARY_INSTALL_DIR}")
    else()
      message("Library will be installed to " "${QCA_LIBRARY_INSTALL_DIR}")
      message("Public headers will be installed to " "${QCA_INCLUDE_INSTALL_DIR}")
      message("Private headers will be installed to " "${QCA_PRIVATE_INCLUDE_INSTALL_DIR}")
    endif()
    message("Feature file will be installed to " "${QCA_FEATURE_INSTALL_DIR}")
    message("Documentation will be installed to " "${QCA_DOC_INSTALL_DIR}")
    message("Man page will be installed to " "${QCA_MAN_INSTALL_DIR}")
    message("Pkg-config file will be installed to " "${PKGCONFIG_INSTALL_PREFIX}")
  endif()
  message("")

  install(EXPORT QCATargets DESTINATION ${QCA_LIBRARY_INSTALL_DIR}/cmake/Qca FILE QcaTargets.cmake)
  install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/Qca/QcaConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/Qca/QcaConfigVersion.cmake"
    DESTINATION ${QCA_LIBRARY_INSTALL_DIR}/cmake/Qca
    )
endif()
