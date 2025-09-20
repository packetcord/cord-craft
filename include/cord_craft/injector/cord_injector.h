//
// Add _Generic compile time polymorphism
//

#ifndef CORD_INJECTOR_H
#define CORD_INJECTOR_H

#include <cord_type.h>
#include <cord_retval.h>

#define CORD_CREATE_INJECTOR CORD_CREATE_INJECTOR_ON_HEAP
#define CORD_DESTROY_INJECTOR CORD_DESTROY_INJECTOR_ON_HEAP

#define CORD_CREATE_INJECTOR_ON_HEAP(id) \
    NEW_ON_HEAP(CordInjector, id)

#define CORD_CREATE_INJECTOR_ON_STACK(id)\
    &NEW_ON_STACK(CordInjector, id)

#define CORD_DESTROY_INJECTOR_ON_HEAP(name)  \
    do {                                     \
        DESTROY_ON_HEAP(CordInjector, name); \
    } while(0)

#define CORD_DESTROY_INJECTOR_ON_STACK(name) \
    do {                                     \
        DESTROY_ON_STACK(CordInjector, name);\
    } while(0)

typedef struct CordInjector CordInjector;

typedef struct
{
    cord_retval_t (*transmit)(CordInjector const * const self, void *buffer, size_t len, ssize_t *transmit_bytes);
} CordInjectorVtbl;

struct CordInjector
{
    const CordInjectorVtbl *vptr;
    uint8_t id;
    int io_handle;
};

static inline cord_retval_t CordInjector_transmit_vcall(CordInjector const * const self, void *buffer, size_t len, ssize_t *transmit_bytes)
{
    return (*(self->vptr->transmit))(self, buffer, len, transmit_bytes);
}

#define CORD_INJECTOR_TRANSMIT_VCALL(self, buffer, len, transmit_bytes)   (*(self->vptr->transmit))((self), (buffer), (len), (transmit_bytes))

#define CORD_INJECTOR_TRANSMIT CORD_INJECTOR_TRANSMIT_VCALL

void CordInjector_ctor(CordInjector * const self, uint8_t id);
void CordInjector_dtor(CordInjector * const self);

#endif // CORD_INJECTOR_H
