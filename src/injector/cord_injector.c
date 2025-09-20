//
// Add _Generic compile time polymorphism
//

#include <injector/cord_injector.h>
#include <cord_retval.h>

static cord_retval_t CordInjector_transmit_(CordInjector const * const self, void *buffer, size_t len, ssize_t *transmit_bytes)
{
#ifdef CORD_INJECTOR_LOG
    CORD_LOG("[CordInjector] transmit()\n");
#endif
    (void)self;
    (void)buffer;
    (void)len;
    (void)transmit_bytes;
    return CORD_OK;
}

void CordInjector_ctor(CordInjector * const self, uint8_t id)
{
#ifdef CORD_INJECTOR_LOG
    CORD_LOG("[CordInjector] ctor()\n");
#endif
    static const CordInjectorVtbl vtbl = {
        .transmit = CordInjector_transmit_,
    };

    self->vptr = &vtbl;
    self->id = id;
}

void CordInjector_dtor(CordInjector * const self)
{
#ifdef CORD_INJECTOR_LOG
    CORD_LOG("[CordInjector] dtor()\n");
#endif
    free(self);
}
