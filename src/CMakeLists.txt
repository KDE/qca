
# base source files

SET( nonmoc_SOURCES
	qca_tools.cpp
	qca_plugin.cpp
	qca_textfilter.cpp
	qca_basic.cpp
	qca_cert.cpp
)

SET( moc_SOURCES
	qca_core.cpp
	qca_publickey.cpp
	qca_keystore.cpp
	qca_securelayer.cpp
	qca_securemessage.cpp
	qca_default.cpp
	support/qpipe.cpp
	support/console.cpp 
  support/synchronizer.cpp
  support/dirwatch/dirwatch.cpp
  support/syncthread.cpp
)

IF (Q_WS_X11)
  SET( nonmoc_SOURCES ${nonmoc_SOURCES} qca_systemstore_flatfile.cpp )
ENDIF(Q_WS_X11)

IF (WIN32)
  SET( moc_SOURCES ${moc_SOURCES} qca_systemstore_win.cpp )
ENDIF(WIN32)

if(APPLE)
  set( nonmoc_SOURCES ${nonmoc_SOURCES} qca_systemstore_mac.cpp)
endif(APPLE)

# Support files
#SET( qca_HEADERS ${qca_HEADERS} support/dirwatch/dirwatch_p.h )

IF (WIN32)
  SET( moc_SOURCES ${moc_SOURCES} support/dirwatch//dirwatch_win.cpp )
ENDIF(WIN32)

IF (UNIX)
  SET( moc_SOURCES ${moc_SOURCES} support/dirwatch//dirwatch_unix.cpp )
ENDIF(UNIX)

# Botan tools
SET( botan_BASE botantools/botan )

ADD_DEFINITIONS(
	-DBOTAN_TYPES_QT
	-DBOTAN_NO_INIT_H
	-DBOTAN_NO_CONF_H
	-DBOTAN_TOOLS_ONLY
	-DBOTAN_MINIMAL_BIGINT
)

ADD_DEFINITIONS(
  -DBOTAN_MP_WORD_BITS=32
  -DBOTAN_VECTOR_OVER_ALLOCATE=4
)

SET( botan_SOURCES
	${botan_BASE}/util.cpp
	${botan_BASE}/exceptn.cpp
	${botan_BASE}/mutex.cpp
	${botan_BASE}/mux_qt/mux_qt.cpp
	${botan_BASE}/secalloc.cpp
	${botan_BASE}/defalloc.cpp
	${botan_BASE}/allocate.cpp
	${botan_BASE}/mp_core.cpp
	${botan_BASE}/mp_comba.cpp
	${botan_BASE}/mp_fkmul.cpp
	${botan_BASE}/mp_mul.cpp
	${botan_BASE}/mp_smul.cpp
	${botan_BASE}/mp_shift.cpp
	${botan_BASE}/mp_misc.cpp
	${botan_BASE}/numthry.cpp
	${botan_BASE}/divide.cpp
	${botan_BASE}/big_base.cpp
	${botan_BASE}/big_code.cpp
	${botan_BASE}/big_io.cpp
	${botan_BASE}/big_ops2.cpp
	${botan_BASE}/big_ops3.cpp
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
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qca_keystore.h")
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qcaprovider.h")
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qca_publickey.h")
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qca_securelayer.h")
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qca_securemessage.h")
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qca_support.h")
qt4_wrap_cpp( SOURCES "${qca_INCLUDEDIR}/QtCrypto/qpipe.h")
qt4_wrap_cpp( SOURCES "support/dirwatch/dirwatch_p.h")

ADD_LIBRARY(qca SHARED ${SOURCES})
INCLUDE_DIRECTORIES(${QT_QTCORE_INCLUDE_DIR} support support/dirwatch ${botan_BASE} )
TARGET_LINK_LIBRARIES(qca ${QT_QTCORE_LIBRARY})

INSTALL(TARGETS qca LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
# FIXME mac
#	LIBS += -framework Carbon -framework Security



 

