PROJECT(QCA)

OPTION(BUILD_TESTS "Create test" OFF)

set(LIB_SUFFIX "" CACHE STRING "Define suffix of directory name (32/64)" )

set(PKGCONFIG_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/pkgconfig/" CACHE STRING "Base directory for pkgconfig files")

#FIND_PACKAGE(Redland REQUIRED)
#FIND_PACKAGE(Raptor REQUIRED)
#FIND_PACKAGE(Rasqal REQUIRED)
FIND_PACKAGE(Qt4 REQUIRED)

if (APPLE)
   find_package(Carbon REQUIRED)
endif (APPLE)

add_definitions (${QT_DEFINITIONS})
INCLUDE_DIRECTORIES(include/QtCrypto/ ${QT_INCLUDES})

# Always include srcdir and builddir in include path
# This saves typing ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY} in about every subdir
set(CMAKE_INCLUDE_CURRENT_DIR ON)

# put the include dirs which are in the source or build tree
# before all other include dirs, so the headers in the sources
# are prefered over the already installed ones
set(CMAKE_INCLUDE_DIRECTORIES_PROJECT_BEFORE ON)

SET(qca_INCLUDEDIR "${CMAKE_CURRENT_SOURCE_DIR}/include" )
SET(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules" )
SET(LIBRARY_OUTPUT_PATH "${CMAKE_BINARY_DIR}/lib${LIB_SUFFIX}" )

set(qca_PLUGINSDIR "${CMAKE_INSTALL_PREFIX}/plugins/lib${LIB_SUFFIX}/crypto/")

include(QcaMacro)

MESSAGE(STATUS "Checking for certstore..")

# fixme add OR mac
IF( WIN32 )
# USE BUILTIN
ELSE ( WIN32 )
  IF ( ENV{QC_CERTSTORE_PATH} )
    IF(EXISTS ENV{QC_CERTSTORE_PATH})
      SET( qca_CERTSTORE $ENV{QC_CERTSTORE_PATH})
    ELSE(EXISTS ENV{QC_CERTSTORE_PATH})
		  # path to try
    ENDIF(EXISTS ENV{QC_CERTSTORE_PATH})
  ELSE( ENV{QC_CERTSTORE_PATH} )
	  SET( toTry
      "/etc/ssl/certs/ca-certificates.crt"
      "/usr/share/ssl/cert.pem"
      "/usr/share/ssl/certs/ca-bundle.crt"
      "/etc/pki/tls/cert.pem"
    )
    FOREACH (_current_try ${${toTry}})
      IF(EXISTS ${_current_try})
        SET( qca_CERTSTORE ${_current_try})
      ENDIF(EXISTS ${_current_try})
    ENDFOREACH (_current_try)
  ENDIF( ENV{QC_CERTSTORE_PATH} )
ENDIF(WIN32)

USE_BUNDLED_CERTSTORE()

IF (qca_CERTSTORE)
  IF( QCA_USING_BUNDLED_CERTSTORE )
    MESSAGE(STATUS "Using built in certstore.")
  ELSE( QCA_USING_BUNDLED_CERTSTORE )
    MESSAGE(STATUS "Using system in certstore.")
  ENDIF( QCA_USING_BUNDLED_CERTSTORE )
  MESSAGE(STATUS "certstore path: " ${qca_CERTSTORE})
  ADD_DEFINITIONS( -DQCA_SYSTEMSTORE_PATH="\\\"${qca_CERTSTORE}\\\"" )
ELSE (qca_CERTSTORE)
  MESSAGE(FATAL_ERROR "Certstore not found")
ENDIF (qca_CERTSTORE)


SET( private_HEADERS ${qca_INCLUDEDIR}/QtCrypto/qca_plugin.h ${qca_INCLUDEDIR}/QtCrypto/qca_systemstore.h )

SET( public_HEADERS 
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

SET( qca_HEADERS ${private_HEADERS} ${public_HEADERS} )

#install public headers only
INSTALL(FILES ${public_HEADERS} DESTINATION "${CMAKE_INSTALL_PREFIX}/include/QtCrypto")

INCLUDE_DIRECTORIES(${QT_QTCORE_INCLUDE_DIR} "${qca_INCLUDEDIR}/QtCrypto")

CONFIGURE_FILE("qca.pc.cmake" "qca.pc" @ONLY)
INSTALL(FILES "${CMAKE_BINARY_DIR}/qca.pc" DESTINATION ${PKGCONFIG_INSTALL_PREFIX})


add_subdirectory(src)
add_subdirectory(tools)
add_subdirectory(plugins)
if(BUILD_TESTS)
        add_subdirectory(unittest)
        add_subdirectory(examples)
endif(BUILD_TESTS)

