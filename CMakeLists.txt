# Checking for user explicitly defined CMAKE_INSTALL_PREFIX
# It must be done before project(...)
if(NOT CMAKE_INSTALL_PREFIX)
  set(QCA_INSTALL_IN_QT_PREFIX ON)
  # If CMAKE_INSTALL_PREFIX is set in cmake arguments
  unset(CMAKE_INSTALL_PREFIX CACHE)
endif()

# The cmake min. version should be set before calling project(...) too
cmake_minimum_required(VERSION 3.4)

project(qca)

set(QCA_LIB_MAJOR_VERSION "2")
set(QCA_LIB_MINOR_VERSION "3")
set(QCA_LIB_PATCH_VERSION "4")

if(POLICY CMP0042)
  cmake_policy(SET CMP0042 OLD)
endif()

option(QT6 "Build with Qt 6" OFF)
option(BUILD_TESTS "Create test" ON)
option(BUILD_TOOLS "Compile mozcerts and qcatool" ON)
set(BUILD_PLUGINS "auto" CACHE STRING "Plugins for building (also possible values: none, all and auto)")
# BUILD_SHARED_LIBS is cmake variable. Need to change default value.
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
endif()

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules" )

# Do not automatically link Qt executables to qtmain target on Windows.
# QCA exucatables use console mode only. Not need to link against qtmain.lib.
if(QT6)
  message(STATUS "Building Qt 6 version")
  find_package(Qt6 COMPONENTS Core Test Core5Compat REQUIRED)
else()
  message(STATUS "Building Qt 5 version")
  set(Qt5_NO_LINK_QTMAIN ON)
  find_package(Qt5 5.14 REQUIRED Core)
endif()

set(CMAKE_AUTOMOC ON)

include(QcaMacro)
include(GNUInstallDirs)
setup_qt_dirs()
if(QT6)
  set(QCA_QT_PC_VERSION "Qt6Core")
  set(QCA_SUFFIX "qt6")
else()
  set(QCA_QT_PC_VERSION "Qt5Core")
  set(QCA_SUFFIX "qt5")
endif()

# QCA can be shared but plugins will be static
# if Qt is static.
if(NOT BUILD_SHARED_LIBS OR QT_IS_STATIC)
  set(STATIC_PLUGINS ON)
  add_definitions(-DQT_STATICPLUGIN)
  set(PLUGIN_TYPE "STATIC")
else()
  set(PLUGIN_TYPE "MODULE")
endif()

set(QCA_SUFFIX "${QCA_SUFFIX}" CACHE STRING "QCA common suffix")
if(QCA_SUFFIX)
  set(QCA_LIB_NAME qca-${QCA_SUFFIX})
  set(QCA_TOOL_NAME qcatool-${QCA_SUFFIX})
  set(MOZCERTS_NAME mozcerts-${QCA_SUFFIX})
  set(QCA_PC_NAME qca2-${QCA_SUFFIX}.pc)
  set(QCA_CONFIG_NAME_BASE "Qca-${QCA_SUFFIX}")
else()
  set(QCA_LIB_NAME qca)
  set(QCA_TOOL_NAME qcatool)
  set(MOZCERTS_NAME mozcerts)
  set(QCA_PC_NAME qca2.pc)
  set(QCA_CONFIG_NAME_BASE "Qca")
endif()

set(QCA_LIB_VERSION_STRING "${QCA_LIB_MAJOR_VERSION}.${QCA_LIB_MINOR_VERSION}.${QCA_LIB_PATCH_VERSION}")

configure_file("include/QtCrypto/qca_version.h.in" "${CMAKE_BINARY_DIR}/qca_version.h")

if (WIN32)
 set(CMAKE_DEBUG_POSTFIX "d")
 add_definitions(-DWIN32_LEAN_AND_MEAN)
elseif (APPLE)
 set(CMAKE_DEBUG_POSTFIX "_debug")
endif()

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
   if (CMAKE_SYSTEM_NAME MATCHES Linux)
     add_definitions (-D_DEFAULT_SOURCE)
     # on arm -Wcast-align throws many internal qt warning
     if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^arm")
       set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wcast-align")
       set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wcast-align")
     endif()

     set ( CMAKE_C_FLAGS     "${CMAKE_C_FLAGS} -Wno-long-long -Wundef -Werror-implicit-function-declaration -Wchar-subscripts -Wall -W -Wpointer-arith -Wwrite-strings -Wformat-security -Wmissing-format-attribute -fno-common")
     set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wnon-virtual-dtor -Wno-long-long -Wundef -Wchar-subscripts -Wall -W -Wpointer-arith -Wwrite-strings -Wformat-security -fno-check-new -fno-common")

     if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
       set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wsuggest-override -Wlogical-op" )
     endif()
   endif()
endif()

add_definitions(-DQT_NO_CAST_TO_ASCII
                -DQT_NO_CAST_FROM_ASCII
                -DQT_NO_URL_CAST_FROM_STRING
                -DQT_NO_CAST_FROM_BYTEARRAY
                -DQT_NO_SIGNALS_SLOTS_KEYWORDS
                -DQT_USE_QSTRINGBUILDER
                -DQT_NO_NARROWING_CONVERSIONS_IN_CONNECT)

if (NOT WIN32)
    # Strict iterators can't be used on Windows, they lead to a link error
    # when application code iterates over a QVector<QPoint> for instance, unless
    # Qt itself was also built with strict iterators.
    # See example at https://bugreports.qt.io/browse/AUTOSUITE-946
    add_definitions(-DQT_STRICT_ITERATORS)
endif()

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
  if(NOT QCA_SUFFIX)
    set(QCA_INCLUDE_INSTALL_DIR "${QT_HEADERS_DIR}" CACHE PATH "Directory where qca public headers will install")
    set(QCA_PRIVATE_INCLUDE_INSTALL_DIR "${QT_HEADERS_DIR}" CACHE PATH "Directory where qca headers will install")
  else()
    set(QCA_INCLUDE_INSTALL_DIR "${QT_HEADERS_DIR}/${QCA_CONFIG_NAME_BASE}" CACHE PATH "Directory where qca public headers will install")
    set(QCA_PRIVATE_INCLUDE_INSTALL_DIR "${QT_HEADERS_DIR}/${QCA_CONFIG_NAME_BASE}" CACHE PATH "Directory where qca headers will install")
  endif()
  set(QCA_DOC_INSTALL_DIR "${QT_DOC_DIR}/html/qca/" CACHE PATH "Directory where qca documentation will install")
  set(QCA_MAN_INSTALL_DIR "${QT_DATA_DIR}/man" CACHE PATH "Directory where qca man pages will install")
else()
  # Cmake says nothing about LIB_SUFFIX
  # de facto it is a standard way to specify lib suffix on many distros
  set(LIB_SUFFIX "" CACHE STRING "Define suffix of directory name (32/64)" )
  set(LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}" CACHE PATH "Directory where lib will install")

  set(QCA_PREFIX_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}" CACHE PATH "Directory where qca will install")
  set(QCA_PLUGINS_INSTALL_DIR "${LIB_INSTALL_DIR}/${QCA_LIB_NAME}" CACHE PATH "Directory where qca plugins will install")
  set(QCA_BINARY_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Directory where qca plugins will install")
  set(QCA_LIBRARY_INSTALL_DIR "${LIB_INSTALL_DIR}" CACHE PATH "Directory where qca library will install")
  set(QCA_FEATURE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/mkspecs/features" CACHE PATH "Directory where qca feature file will install")
  if(NOT QCA_SUFFIX)
    set(QCA_INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Directory where qca public headers will install")
    set(QCA_PRIVATE_INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Directory where qca headers will install")
  else()
    set(QCA_INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/include/${QCA_CONFIG_NAME_BASE}" CACHE PATH "Directory where qca public headers will install")
    set(QCA_PRIVATE_INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/include/${QCA_CONFIG_NAME_BASE}" CACHE PATH "Directory where qca headers will install")
  endif()
  set(QCA_DOC_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/share/doc/${QCA_LIB_NAME}/html" CACHE PATH "Directory where qca documentation will install")
  set(QCA_MAN_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/share/man" CACHE PATH "Directory where qca man pages will install")
endif()

set(PKGCONFIG_INSTALL_PREFIX "${QCA_LIBRARY_INSTALL_DIR}/pkgconfig" CACHE PATH "Base directory for pkgconfig files")

normalize_path(QCA_PREFIX_INSTALL_DIR)

if(OSX_FRAMEWORK)
  set(QCA_FULL_INCLUDE_INSTALL_DIR "${QCA_LIBRARY_INSTALL_DIR}/${QCA_LIB_NAME}.framework/Headers")
else()
  set(QCA_FULL_INCLUDE_INSTALL_DIR "${QCA_INCLUDE_INSTALL_DIR}/QtCrypto")
endif()

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
    set(PKGCONFIG_CFLAGS "-F\${libdir} -I\${includedir}")
    set(PKGCONFIG_LIBS "-F\${libdir} -framework ${QCA_LIB_NAME}")
  else()
    set(PKGCONFIG_CFLAGS "-I\${includedir}")
    set(PKGCONFIG_LIBS "-L\${libdir} -l${QCA_LIB_NAME}")
  endif()

  if(NOT QT6)
    # qca2.pc uses absolute paths. So it must be there. Don't rellocate this.
    configure_file("qca2.pc.cmake" "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/pkgconfig/${QCA_PC_NAME}" @ONLY)
    if(NOT DEVELOPER_MODE)
      install(FILES "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/pkgconfig/${QCA_PC_NAME}" DESTINATION ${PKGCONFIG_INSTALL_PREFIX})
    endif()
  endif()
endif()

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
   set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
endif()

message(STATUS "Checking for certstore..")
# fixme add OR mac
if( WIN32 )
    # USE BUILTIN
else()
  if ( DEFINED ENV{QC_CERTSTORE_PATH} )
    if(EXISTS $ENV{QC_CERTSTORE_PATH})
      set( qca_CERTSTORE $ENV{QC_CERTSTORE_PATH})
    endif()
  else()
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
      endif()
    endforeach (_current_try)
  endif()
endif()

if (qca_CERTSTORE)
  message(STATUS "Found system certstore")
else()
  message(STATUS "Using built in certstore.")
  set( qca_CERTSTORE "${CMAKE_CURRENT_SOURCE_DIR}/certs/rootcerts.pem")
  # note that INSTALL_FILES targets are relative to the current installation prefix...
  if(NOT DEVELOPER_MODE)
    install(FILES "${qca_CERTSTORE}" DESTINATION "${QCA_PREFIX_INSTALL_DIR}/certs")
  endif()
endif()
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

include_directories("${qca_INCLUDEDIR}/QtCrypto")

if(NOT QT6)
  configure_file("crypto.prf.cmake" "${CMAKE_BINARY_DIR}/mkspecs/features/crypto.prf" @ONLY)
  if(NOT DEVELOPER_MODE)
    install(FILES "${CMAKE_BINARY_DIR}/mkspecs/features/crypto.prf" DESTINATION "${QCA_FEATURE_INSTALL_DIR}")
  endif()
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
    endif()
  endforeach(PLUGIN IN LISTS PLUGINS)
endif()

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(unittest)
  add_subdirectory(examples)
endif()
if(BUILD_TOOLS)
  add_subdirectory(tools)
endif()

if(DOXYGEN_FOUND)
  configure_file(${CMAKE_SOURCE_DIR}/Doxyfile.in ${CMAKE_BINARY_DIR}/Doxyfile @ONLY)
  add_custom_target(doc
    ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/Doxyfile
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/docs/pics
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/docs/pics/qca-arch.eps ${CMAKE_BINARY_DIR}/docs/pics/qca-arch.eps
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/docs/pics/qca-arch.png ${CMAKE_BINARY_DIR}/docs/pics/qca-arch.png
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Generating API documentation with Doxygen" VERBATIM)
endif()

include(CMakePackageConfigHelpers)
configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/QcaConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/${QCA_CONFIG_NAME_BASE}/${QCA_CONFIG_NAME_BASE}Config.cmake"
  INSTALL_DESTINATION ${QCA_LIBRARY_INSTALL_DIR}/cmake/${QCA_CONFIG_NAME_BASE}
)
write_basic_config_version_file("${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/${QCA_CONFIG_NAME_BASE}/${QCA_CONFIG_NAME_BASE}ConfigVersion.cmake" VERSION ${QCA_LIB_VERSION_STRING} COMPATIBILITY AnyNewerVersion)

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
  endif()

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

  if(UNIX AND NOT APPLE)
    if(NOT QCA_SUFFIX)

      message("${ESCAPE}[31mYou don't have QCA_SUFFIX set. Please note that the recommended way of")
      if(QT6)
        message("building Qt6 version of qca for Linux distributions is to set")
        message("QCA_SUFFIX to qt6 (-DQCA_SUFFIX=qt6).")
      else()
        message("building Qt5 version of qca for Linux distributions is to set")
        message("QCA_SUFFIX to qt5 (-DQCA_SUFFIX=qt5).")
      endif()
      message("${ESCAPE}[0m")
    endif()
  endif()

  install(EXPORT ${QCA_CONFIG_NAME_BASE}Targets DESTINATION ${QCA_LIBRARY_INSTALL_DIR}/cmake/${QCA_CONFIG_NAME_BASE} FILE ${QCA_CONFIG_NAME_BASE}Targets.cmake)
  install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/${QCA_CONFIG_NAME_BASE}/${QCA_CONFIG_NAME_BASE}Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/${QCA_CONFIG_NAME_BASE}/${QCA_CONFIG_NAME_BASE}ConfigVersion.cmake"
    DESTINATION ${QCA_LIBRARY_INSTALL_DIR}/cmake/${QCA_CONFIG_NAME_BASE}
    )
endif()
