/*************************************************
* Qt Thread Mutex Header File                    *
* (C) 1999-2004 The Botan Project                *
*************************************************/

#include <botan/mutex.h>

#ifndef BOTAN_EXT_MUTEX_QT_H__
#define BOTAN_EXT_MUTEX_QT_H__

namespace Botan {

/*************************************************
* Qt Mutex                                       *
*************************************************/
class Qt_Mutex : public Mutex
   {
   public:
      void lock();
      void unlock();
      Mutex* clone() const { return new Qt_Mutex; }

      Qt_Mutex();
      ~Qt_Mutex();
   private:
      struct mutex_wrapper* mutex;
   };

}

#endif
