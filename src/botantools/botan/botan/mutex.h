/*
Copyright (C) 1999-2007 The Botan Project. All rights reserved.

Redistribution and use in source and binary forms, for any use, with or without
modification, is permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions, and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions, and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE DISCLAIMED.

IN NO EVENT SHALL THE AUTHOR(S) OR CONTRIBUTOR(S) BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
// LICENSEHEADER_END
namespace QCA { // WRAPNS_LINE
/*************************************************
 * Mutex Header File                              *
 * (C) 1999-2007 The Botan Project                *
 *************************************************/

#ifndef BOTAN_MUTEX_H__
#define BOTAN_MUTEX_H__

} // WRAPNS_LINE
#include <botan/exceptn.h>
namespace QCA { // WRAPNS_LINE

namespace Botan {

/*************************************************
 * Mutex Base Class                               *
 *************************************************/
class Mutex
{
public:
    virtual void lock()   = 0;
    virtual void unlock() = 0;
    virtual ~Mutex()
    {
    }
};

/*************************************************
 * Mutex Factory                                  *
 *************************************************/
class Mutex_Factory
{
public:
    virtual Mutex *make() = 0;
    virtual ~Mutex_Factory()
    {
    }
};

/*************************************************
 * Default Mutex Factory                          *
 *************************************************/
class Default_Mutex_Factory : public Mutex_Factory
{
public:
    Mutex *make() override;
};

/*************************************************
 * Mutex Holding Class                            *
 *************************************************/
class Mutex_Holder
{
public:
    Mutex_Holder(Mutex *);
    ~Mutex_Holder();

    Mutex_Holder(const Mutex_Holder &)            = delete;
    Mutex_Holder &operator=(const Mutex_Holder &) = delete;

private:
    Mutex *mux;
};

/*************************************************
 * Named Mutex Holder                             *
 *************************************************/
#ifndef BOTAN_NO_LIBSTATE
class Named_Mutex_Holder
{
public:
    Named_Mutex_Holder(const std::string &);
    ~Named_Mutex_Holder();

private:
    const std::string mutex_name;
};
#endif

}

#endif
} // WRAPNS_LINE
