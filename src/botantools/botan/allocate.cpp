/*************************************************
* Allocator Factory Source File                  *
* (C) 1999-2004 The Botan Project                *
*************************************************/

#include <botan/allocate.h>
#include <botan/secalloc.h>
#include <botan/defalloc.h>
#include <botan/mutex.h>
#ifndef BOTAN_NO_INIT_H
# include <botan/init.h>
#endif
#include <map>

namespace Botan {

namespace {

/*************************************************
* A factory for creating SecureAllocators        *
*************************************************/
class AllocatorFactory
   {
   public:
      SecureAllocator* get(const std::string& type) const
         {
         Mutex_Holder lock(factory_lock);
         std::map<std::string, SecureAllocator*>::const_iterator iter;
         iter = alloc.find(type);
         if(iter == alloc.end())
            return 0;
         return iter->second;
         }
      void add(const std::string& type, SecureAllocator* allocator)
         {
         Mutex_Holder lock(factory_lock);
         allocator->init();
         alloc[type] = allocator;
         }
      AllocatorFactory() { factory_lock = get_mutex(); }
      ~AllocatorFactory()
         {
         std::map<std::string, SecureAllocator*>::iterator iter;
         for(iter = alloc.begin(); iter != alloc.end(); iter++)
            {
            iter->second->destroy();
            delete iter->second;
            }
         delete factory_lock;
         }
   private:
      std::map<std::string, SecureAllocator*> alloc;
      Mutex* factory_lock;
   };

AllocatorFactory* factory = 0;
std::string default_type = "default";

/*************************************************
* Try to get an allocator of the specified type  *
*************************************************/
SecureAllocator* try_alloc(const std::string& type)
   {
   if(!factory)
      throw Invalid_State("Library has not been initialized, or it failed");
   SecureAllocator* alloc = factory->get(type);
   if(alloc)
      return alloc;
   return 0;
   }

}

/*************************************************
* Get an allocator                               *
*************************************************/
SecureAllocator* get_allocator(const std::string& type)
   {
   SecureAllocator* alloc;

   if(type != "")
      {
      alloc = try_alloc(type);
      if(alloc) return alloc;
      }

   alloc = try_alloc(default_type);
   if(alloc) return alloc;

   alloc = try_alloc("malloc");
   if(alloc) return alloc;

   throw Exception("Couldn't find an allocator to use in get_allocator");
   }

/*************************************************
* Set the default allocator type                 *
*************************************************/
std::string set_default_allocator(const std::string& type)
   {
   std::string old_default = default_type;
   default_type = type;
   return old_default;
   }

/*************************************************
* Add new allocator type                         *
*************************************************/
bool add_allocator_type(const std::string& type, SecureAllocator* alloc)
   {
   if(type == "" || factory->get(type))
      return false;
   factory->add(type, alloc);
   return true;
   }

namespace Init {

/*************************************************
* Initialize the memory subsystem                *
*************************************************/
void startup_memory_subsystem()
   {
   factory = new AllocatorFactory;
   factory->add("malloc", new Malloc_Allocator);
   factory->add("locking", new Locking_Allocator);
   }

/*************************************************
* Shut down the memory subsystem                 *
*************************************************/
void shutdown_memory_subsystem()
   {
   delete factory;
   factory = 0;
   }

}

}
