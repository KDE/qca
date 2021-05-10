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
endif()

if(DEVELOPER_MODE)
  add_definitions(-DQCA_PLUGIN_PATH="${CMAKE_BINARY_DIR}/lib/${QCA_LIB_NAME}")
else()
  if(USE_RELATIVE_PATHS)
    add_definitions(-DQCA_PLUGIN_PATH="${QCA_PREFIX_INSTALL_DIR}/${QCA_PLUGINS_INSTALL_DIR}")
  else()
    add_definitions(-DQCA_PLUGIN_PATH="${QCA_PLUGINS_INSTALL_DIR}")
  endif()
endif()

# base source files


SET( SOURCES
	qca_tools.cpp
	qca_plugin.cpp
	qca_textfilter.cpp
	qca_basic.cpp
	support/logger.cpp
	qca_cert.cpp
	qca_core.cpp
	qca_default.cpp
	qca_keystore.cpp
	qca_publickey.cpp
	qca_safeobj.cpp
	qca_safetimer.cpp
	qca_securelayer.cpp
	qca_securemessage.cpp
	support/qpipe.cpp
	support/console.cpp
	support/synchronizer.cpp
	support/dirwatch.cpp
	support/syncthread.cpp
)

IF (WIN32)
  SET( SOURCES ${SOURCES} qca_systemstore_win.cpp )
elseif(APPLE)
  set( SOURCES ${SOURCES} qca_systemstore_mac.cpp)
else()
  SET( SOURCES ${SOURCES} qca_systemstore_flatfile.cpp )
endif()

# Support files
#SET( qca_HEADERS ${qca_HEADERS} support/dirwatch/dirwatch_p.h )

# Botan tools
SET( botan_BASE botantools/botan )


INCLUDE_DIRECTORIES(support ${botan_BASE} )

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
endif()

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

SET( SOURCES ${SOURCES} ${botan_SOURCES})

add_library(${QCA_LIB_NAME} ${SOURCES}  ${public_HEADERS})
if(QT6)
  target_link_libraries(${QCA_LIB_NAME} Qt6::Core Qt6::Core5Compat)
else()
  target_link_libraries(${QCA_LIB_NAME} Qt5::Core)
endif()

if(WIN32)
	TARGET_LINK_LIBRARIES(${QCA_LIB_NAME} crypt32 ws2_32)
endif()

if(APPLE)
  set(COREFOUNDATION_LIBRARY "-framework CoreFoundation")
  set(COREFOUNDATION_LIBRARY_SECURITY "-framework Security")
  TARGET_LINK_LIBRARIES(${QCA_LIB_NAME} ${COREFOUNDATION_LIBRARY} ${COREFOUNDATION_LIBRARY_SECURITY})

  if(NOT USE_RELATIVE_PATHS)
    set_target_properties(${QCA_LIB_NAME} PROPERTIES
                          INSTALL_NAME_DIR "${QCA_LIBRARY_INSTALL_DIR}"
    )
  endif()
endif()

if(NOT ANDROID)
  set_target_properties(${QCA_LIB_NAME} PROPERTIES
                        VERSION ${QCA_LIB_MAJOR_VERSION}.${QCA_LIB_MINOR_VERSION}.${QCA_LIB_PATCH_VERSION}
                        SOVERSION ${QCA_LIB_MAJOR_VERSION}
                        )
endif()

set_target_properties(${QCA_LIB_NAME} PROPERTIES
                      DEFINE_SYMBOL QCA_MAKEDLL
                      PUBLIC_HEADER "${public_HEADERS}"
                      FRAMEWORK ${OSX_FRAMEWORK}
                      FRAMEWORK_VERSION ${QCA_LIB_MAJOR_VERSION}
                      EXPORT_NAME ${QCA_LIB_NAME}
                      )

if(NOT DEVELOPER_MODE)
  # Do not split 'PUBLIC_HEADER ...' line. It means install headers to folder
  # and set this folder as -I flag for imported target.
  # Also EXPORT doesn't actually install any files. It only created a new target.
  install(TARGETS ${QCA_LIB_NAME} EXPORT ${QCA_CONFIG_NAME_BASE}Targets
          LIBRARY DESTINATION "${QCA_LIBRARY_INSTALL_DIR}"
          RUNTIME DESTINATION "${QCA_BINARY_INSTALL_DIR}"
          ARCHIVE DESTINATION "${QCA_LIBRARY_INSTALL_DIR}"
          FRAMEWORK DESTINATION "${QCA_LIBRARY_INSTALL_DIR}"
          PUBLIC_HEADER DESTINATION "${QCA_FULL_INCLUDE_INSTALL_DIR}" INCLUDES DESTINATION "${QCA_FULL_INCLUDE_INSTALL_DIR}"
  )
  install_pdb(${QCA_LIB_NAME} ${QCA_BINARY_INSTALL_DIR})
endif()

