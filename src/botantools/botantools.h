#ifndef BOTANTOOLS_H
#define BOTANTOOLS_H

#include <qglobal.h>
#include <botan/mutex.h>
#include <botan/mux_qt.h>
#include <botan/allocate.h>
#include <botan/secmem.h>
#include <botan/bigint.h>
#ifdef Q_OS_UNIX
# include <botan/mmap_mem.h>
#endif

namespace QCA
{
	namespace Botan
	{
		namespace Init
		{
			void set_mutex_type(Mutex*);
			void startup_memory_subsystem();
			void shutdown_memory_subsystem();
		}

		extern int botan_memory_chunk;
		extern int botan_prealloc;
	}
}

#endif
