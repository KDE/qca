/*
 * Copyright (C) 2006  Alon Bar-Lev <alon.barlev@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef __PKCS11H_HELPER_CONFIG_H
#define __PKCS11H_HELPER_CONFIG_H

#if !defined(PKCS11H_NO_NEED_INCLUDE_CONFIG)

#if !defined(WIN32) && defined(_WIN32)
#define WIN32
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#if defined(WIN32)
#include <windows.h>
#include <process.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#endif

#endif /* PKCS11H_NO_NEED_INCLUDE_CONFIG */

#define ENABLE_PKCS11H_HELPER

#ifdef ENABLE_PKCS11H_HELPER

#include <openssl/x509.h>

#undef PKCS11H_USE_CYGWIN	/* cygwin is not supported */

#if !defined(FALSE)
#define FALSE 0
#endif
#if !defined(TRUE)
#define TRUE (!FALSE)
#endif

typedef int PKCS11H_BOOL;

#if !defined(IN)
#define IN
#endif
#if !defined(OUT)
#define OUT
#endif

#define ENABLE_PKCS11H_DEBUG
#define ENABLE_PKCS11H_THREADING
#define ENABLE_PKCS11H_TOKEN
#undef  ENABLE_PKCS11H_DATA
#define ENABLE_PKCS11H_CERTIFICATE
#undef  ENABLE_PKCS11H_LOCATE
#define ENABLE_PKCS11H_ENUM
#define ENABLE_PKCS11H_SLOTEVENT
#undef  ENABLE_PKCS11H_OPENSSL
#undef  ENABLE_PKCS11H_STANDALONE

#define PKCS11H_ASSERT		assert
#define PKCS11H_TIME		time

#if defined(WIN32) || defined(PKCS11H_USE_CYGWIN)
#include "cryptoki-win32.h"
#else
#include "cryptoki.h"
#endif

#endif		/* ENABLE_PKCS11H_HELPER */
#endif		/* __PKCS11H_HELPER_CONFIG_H */
