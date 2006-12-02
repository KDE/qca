
# - Try to find the Gcrypt library
# Once run this will define
#
#  LIBGCRYPT_FOUND - set if the system has the gcrypt library
#  LIBGCRYPT_CFLAGS - the required gcrypt compilation flags
#  LIBGCRYPT_LIBRARIES - the linker libraries needed to use the gcrypt library
#
# Copyright (c) 2006 Brad Hards <bradh@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

# libgcrypt is moving to pkg-config, but earlier version don't have it

#search in typical paths for libgcrypt-config
FIND_PROGRAM(LIBGCRYPTCONFIG_EXECUTABLE NAMES libgcrypt-config PATHS
   /usr/bin
   /usr/local/bin
)

#reset variables
set(LIBGCRYPT_LIBRARIES)
set(LIBGCRYPT_CFLAGS)

# if libgcrypt-config has been found
IF(LIBGCRYPTCONFIG_EXECUTABLE)

  EXEC_PROGRAM(${LIBGCRYPTCONFIG_EXECUTABLE} ARGS --libs RETURN_VALUE _return_VALUE OUTPUT_VARIABLE LIBGCRYPT_LIBRARIES)

  EXEC_PROGRAM(${LIBGCRYPTCONFIG_EXECUTABLE} ARGS --cflags RETURN_VALUE _return_VALUE OUTPUT_VARIABLE LIBGCRYPT_CFLAGS)

  IF(LIBGCRYPT_LIBRARIES AND LIBGCRYPT_CFLAGS)
    SET(LIBGCRYPT_FOUND TRUE)
    message(STATUS "Found libgcrypt: ${LIBGCRYPT_LIBRARIES}")
  ENDIF(LIBGCRYPT_LIBRARIES AND LIBGCRYPT_CFLAGS)

  MARK_AS_ADVANCED(LIBGCRYPT_CFLAGS LIBGCRYPT_LIBRARIES)

ENDIF(LIBGCRYPTCONFIG_EXECUTABLE)
