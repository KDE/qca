/*************************************************
* Allocator Factory Header File                  *
* (C) 1999-2004 The Botan Project                *
*************************************************/

#ifndef BOTAN_ALLOCATION_H__
#define BOTAN_ALLOCATION_H__

#include <botan/secalloc.h>

namespace Botan {

/*************************************************
* Get an allocator                               *
*************************************************/
SecureAllocator* get_allocator(const std::string& = "");

/*************************************************
* Set the default allocator type                 *
*************************************************/
std::string set_default_allocator(const std::string&);

/*************************************************
* Add new allocator type                         *
*************************************************/
bool add_allocator_type(const std::string&, SecureAllocator*);

}

#endif
