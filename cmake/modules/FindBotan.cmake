
# - Try to find the Gcrypt library
# Once run this will define
#
#  BOTAN_FOUND - set if the system has the gcrypt library
#  BOTAN_CFLAGS - the required gcrypt compilation flags
#  BOTAN_LIBRARIES - the linker libraries needed to use the gcrypt library
#
# Copyright (c) 2006 Brad Hards <bradh@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

# libgcrypt is moving to pkg-config, but earlier version don't have it

#search in typical paths for libgcrypt-config
FIND_PROGRAM(BOTANCONFIG_EXECUTABLE NAMES botan-config)

#reset variables
set(BOTAN_LIBRARIES)
set(BOTAN_CFLAGS)

# if botan-config has been found
IF(BOTANCONFIG_EXECUTABLE)

  EXEC_PROGRAM(${BOTANCONFIG_EXECUTABLE} ARGS --libs RETURN_VALUE _return_VALUE OUTPUT_VARIABLE BOTAN_LIBRARIES)

  EXEC_PROGRAM(${BOTANCONFIG_EXECUTABLE} ARGS --cflags RETURN_VALUE _return_VALUE OUTPUT_VARIABLE BOTAN_CFLAGS)

  IF(BOTAN_LIBRARIES)
    SET(BOTAN_FOUND TRUE)
  ENDIF(BOTAN_LIBRARIES)

  MARK_AS_ADVANCED(BOTAN_CFLAGS BOTAN_LIBRARIES)

ENDIF(BOTANCONFIG_EXECUTABLE)

if (BOTAN_FOUND)
   if (NOT Botan_FIND_QUIETLY)
     message(STATUS "Found Botan: ${BOTAN_LIBRARIES}")
   endif (NOT Botan_FIND_QUIETLY)
else (BOTAN_FOUND)
   if (Botan_FIND_REQUIRED)
      message(FATAL_ERROR "Could not find Botan libraries")
   endif (Botan_FIND_REQUIRED)
endif (BOTAN_FOUND)


