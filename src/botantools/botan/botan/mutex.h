/*************************************************
* Mutex Header File                              *
* (C) 1999-2004 The Botan Project                *
*************************************************/

#ifndef BOTAN_MUTEX_H__
#define BOTAN_MUTEX_H__

namespace Botan {

/*************************************************
* Mutex Base Class                               *
*************************************************/
class Mutex
   {
   public:
      virtual void lock() = 0;
      virtual void unlock() = 0;
      virtual Mutex* clone() const = 0;
      virtual ~Mutex() {}
   };

/*************************************************
* Mutex Holding Class                            *
*************************************************/
class Mutex_Holder
   {
   public:
      Mutex_Holder(Mutex* m) : mux(m) { mux->lock(); }
      ~Mutex_Holder() { mux->unlock(); }
   private:
      Mutex* mux;
   };

/*************************************************
* Get/set a mutex                                *
*************************************************/
Mutex* get_mutex();
void initialize_mutex(Mutex*&);

}

#endif
