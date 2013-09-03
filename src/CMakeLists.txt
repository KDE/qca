include(CheckIncludeFiles)
CHECK_INCLUDE_FILES(sys/filio.h HAVE_SYS_FILIO_H)
IF(HAVE_SYS_FILIO_H)
  ADD_DEFINITIONS(-DHAVE_SYS_FILIO_H)
ENDIF(HAVE_SYS_FILIO_H)

INCLUDE(CheckCXXSourceCompiles)
CHECK_CXX_SOURCE_COMPILES("
# include <stdlib.h>
# include <sys/mman.h>
int main() { void *f = 0; return mlock(f,8); }
" MLOCK_TAKES_VOID)
if(NOT MLOCK_TAKES_VOID)
  MESSAGE(STATUS "mlock(2) does not take a void *")
  ADD_DEFINITIONS(-DMLOCK_NOT_VOID_PTR)
endif(NOT MLOCK_TAKES_VOID)

configure_file(config-qca.h.cmake "${CMAKE_CURRENT_BINARY_DIR}/config-qca.h" @ONLY)

# base source files


SET( nonmoc_SOURCES
	qca_tools.cpp
	qca_plugin.cpp
	qca_textfilter.cpp
	qca_basic.cpp
	qca_safeobj.cpp
	support/logger.cpp
)

SET( moc_SOURCES
	qca_cert.cpp
	qca_core.cpp
	qca_default.cpp
	qca_keystore.cpp
	qca_publickey.cpp
	qca_securelayer.cpp
	qca_securemessage.cpp
	support/qpipe.cpp
	support/console.cpp 
	support/synchronizer.cpp
	support/dirwatch.cpp
	support/syncthread.cpp
)

IF (WIN32)
  SET( moc_SOURCES ${moc_SOURCES} qca_systemstore_win.cpp )
elseif(APPLE)
  set( nonmoc_SOURCES ${nonmoc_SOURCES} qca_systemstore_mac.cpp)
else()
  SET( nonmoc_SOURCES ${nonmoc_SOURCES} qca_systemstore_flatfile.cpp )
endif()

# Support files
#SET( qca_HEADERS ${qca_HEADERS} support/dirwatch/dirwatch_p.h )

# Botan tools
SET( botan_BASE botantools/botan )


INCLUDE_DIRECTORIES(${QT_QTCORE_INCLUDE_DIR} support ${botan_BASE} )

ADD_DEFINITIONS(
	-DBOTAN_TYPES_QT
	-DBOTAN_NO_INIT_H
	-DBOTAN_NO_CONF_H
	-DBOTAN_TOOLS_ONLY
	-DBOTAN_MINIMAL_BIGINT
)

ADD_DEFINITIONS(
  -DBOTAN_MP_WORD_BITS=32
  -DBOTAN_KARAT_MUL_THRESHOLD=12
  -DBOTAN_KARAT_SQR_THRESHOLD=12
  -DBOTAN_EXT_MUTEX_QT
)

if(UNIX)
   ADD_DEFINITIONS( -DBOTAN_EXT_ALLOC_MMAP)
endif(UNIX)

SET( botan_SOURCES
	${botan_BASE}/util.cpp
	${botan_BASE}/exceptn.cpp
	${botan_BASE}/mutex.cpp
	${botan_BASE}/mux_qt/mux_qt.cpp
	${botan_BASE}/charset.cpp
	${botan_BASE}/defalloc.cpp
	${botan_BASE}/mp_comba.cpp
	${botan_BASE}/mp_mul.cpp
	${botan_BASE}/mp_shift.cpp
	${botan_BASE}/mp_misc.cpp
	${botan_BASE}/divide.cpp
	${botan_BASE}/big_base.cpp
	${botan_BASE}/big_code.cpp
	${botan_BASE}/big_io.cpp
	${botan_BASE}/big_ops2.cpp
	${botan_BASE}/big_ops3.cpp
	${botan_BASE}/bit_ops.cpp
	${botan_BASE}/libstate.cpp
	${botan_BASE}/mem_pool.cpp
	${botan_BASE}/modules.cpp
	${botan_BASE}/mp_asm.cpp
	${botan_BASE}/mp_mulop.cpp
	${botan_BASE}/parsing.cpp
)

IF (UNIX)
  SET( botan_SOURCES ${botan_SOURCES} ${botan_BASE}/ml_unix/mlock.cpp)
  SET( botan_SOURCES ${botan_SOURCES} ${botan_BASE}/alloc_mmap/mmap_mem.cpp)
ENDIF (UNIX)

IF(WIN32)
  SET( botan_SOURCES ${botan_SOURCES} ${botan_BASE}/ml_win32/mlock.cpp)
ENDIF(WIN32)

MY_AUTOMOC( moc_SOURCES )
SET( SOURCES ${SOURCES} ${moc_SOURCES} ${nonmoc_SOURCES} )

SET( SOURCES ${SOURCES} ${botan_SOURCES})

qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qca_core.h")
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qca_cert.h")
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qca_keystore.h")
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qcaprovider.h")
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qca_publickey.h")
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qca_securelayer.h")
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qca_securemessage.h")
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qca_support.h")
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qpipe.h")
qt4_wrap_cpp( SOURCES "qca_safeobj.h")

ADD_LIBRARY(${QCA_LIB_NAME} SHARED ${SOURCES})
TARGET_LINK_LIBRARIES(${QCA_LIB_NAME} ${QT_QTCORE_LIBRARY})

if(WIN32)
	TARGET_LINK_LIBRARIES(${QCA_LIB_NAME} crypt32 ws2_32)
endif(WIN32)	

if(APPLE)
   set(CARBON_LIBRARY_SECURITY "-framework Security")
   TARGET_LINK_LIBRARIES(${QCA_LIB_NAME} ${CARBON_LIBRARY} ${CARBON_LIBRARY_SECURITY})
endif(APPLE)

set_target_properties(${QCA_LIB_NAME} PROPERTIES
                      VERSION ${QCA_LIB_MAJOR_VERSION}.${QCA_LIB_MINOR_VERSION}.${QCA_LIB_PATCH_VERSION}
                      SOVERSION ${QCA_LIB_MAJOR_VERSION}
                      DEFINE_SYMBOL QCA_MAKEDLL
                      )

INSTALL(TARGETS ${QCA_LIB_NAME}
   LIBRARY DESTINATION "${QCA_LIBRARY_INSTALL_DIR}"
   RUNTIME DESTINATION "${QCA_BINARY_INSTALL_DIR}"
   ARCHIVE DESTINATION "${QCA_LIBRARY_INSTALL_DIR}"
)
