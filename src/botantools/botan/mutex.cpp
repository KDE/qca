/*************************************************
* Mutex Source File                              *
* (C) 1999-2004 The Botan Project                *
*************************************************/

#include <botan/mutex.h>
#include <botan/exceptn.h>

#ifndef BOTAN_NO_INIT_H
# include <botan/init.h>
#endif

namespace Botan {

namespace {

/*************************************************
* Global Mutex Variables                         *
*************************************************/
Mutex* mutex_factory = 0;
Mutex* mutex_init_lock = 0;

/*************************************************
* Default Mutex                                  *
*************************************************/
class Default_Mutex : public Mutex
   {
   public:
      void lock();
      void unlock();
      Mutex* clone() const { return new Default_Mutex; }
      Default_Mutex() { locked = false; }
   private:
      bool locked;
   };

/*************************************************
* Lock the mutex                                 *
*************************************************/
void Default_Mutex::lock()
   {
   if(locked)
      {
      abort();
      throw Internal_Error("Default_Mutex::lock: Mutex is already locked");
      }
   locked = true;
   }

/*************************************************
* Unlock the mutex                               *
*************************************************/
void Default_Mutex::unlock()
   {
   if(!locked)
      {
      abort();
      throw Internal_Error("Default_Mutex::unlock: Mutex is already unlocked");
      }
   locked = false;
   }

}

/*************************************************
* Get a mew mutex                                *
*************************************************/
Mutex* get_mutex()
   {
   if(mutex_factory == 0)
      return new Default_Mutex;
   return mutex_factory->clone();
   }

/*************************************************
* Initialize a mutex atomically                  *
*************************************************/
void initialize_mutex(Mutex*& mutex)
   {
   if(mutex) return;

   if(mutex_init_lock)
      {
      Mutex_Holder lock(mutex_init_lock);
      if(mutex == 0)
         mutex = get_mutex();
      }
   else
      mutex = get_mutex();
   }

namespace Init {

/*************************************************
* Set the Mutex type                             *
*************************************************/
void set_mutex_type(Mutex* mutex)
   {
   delete mutex_factory;
   delete mutex_init_lock;

   mutex_factory = mutex;

   if(mutex) mutex_init_lock = get_mutex();
   else      mutex_init_lock = 0;
   }

}

}
