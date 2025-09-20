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
    cord_retval_t (*tx)(CordInjector const * const self, void *buffer, size_t len, ssize_t *tx_bytes);
} CordInjectorVtbl;

struct CordInjector
{
    const CordInjectorVtbl *vptr;
    uint8_t id;
    int io_handle;
};

static inline cord_retval_t CordInjector_tx_vcall(CordInjector const * const self, void *buffer, size_t len, ssize_t *tx_bytes)
{
    return (*(self->vptr->tx))(self, buffer, len, tx_bytes);
}

#define CORD_INJECTOR_TX_VCALL(self, buffer, len, tx_bytes)   (*(self->vptr->tx))((self), (buffer), (len), (tx_bytes))

#define CORD_INJECTOR_TX CORD_INJECTOR_TX_VCALL

void CordInjector_ctor(CordInjector * const self, uint8_t id);
void CordInjector_dtor(CordInjector * const self);

#endif // CORD_INJECTOR_H
