#ifndef CORD_L3_STACK_INJECTOR_H
#define CORD_L3_STACK_INJECTOR_H

#include <injector/cord_injector.h>

#define CORD_CREATE_L3_STACK_INJECTOR CORD_CREATE_L3_STACK_INJECTOR_ON_HEAP
#define CORD_DESTROY_L3_STACK_INJECTOR CORD_DESTROY_L3_STACK_INJECTOR_ON_HEAP

#define CORD_CREATE_L3_STACK_INJECTOR_ON_HEAP(id) \
    (CordInjector *) NEW_ON_HEAP(CordL3StackInjector, id)

#define CORD_CREATE_L3_STACK_INJECTOR_ON_STACK(id)\
    (CordInjector *) &NEW_ON_STACK(CordL3StackInjector, id)

#define CORD_DESTROY_L3_STACK_INJECTOR_ON_HEAP(name) \
    do {                                             \
        DESTROY_ON_HEAP(CordL3StackInjector, name);  \
    } while(0)

#define CORD_DESTROY_L3_STACK_INJECTOR_ON_STACK(name)\
    do {                                             \
        DESTROY_ON_STACK(CordL3StackInjector, name); \
    } while(0)

typedef struct
{
    void (*set_target_ipv4)(struct CordInjector * const self, in_addr_t ipv4_addr);
    void (*set_target_ipv6)(struct CordInjector * const self, struct in6_addr ipv6_addr);
} CordL3StackInjectorVtbl;

typedef struct CordL3StackInjector
{
    CordInjector base;
    const CordL3StackInjectorVtbl *vptr;
    struct sockaddr_in dst_addr_in;
    struct sockaddr_in6 dst_addr_in6;
    in_addr_t ipv4_dst_addr;
    struct in6_addr ipv6_dst_addr;
} CordL3StackInjector;

void CordL3StackInjector_ctor(CordL3StackInjector * const self, uint8_t id);
void CordL3StackInjector_dtor(CordL3StackInjector * const self);

#define CORD_L3_STACK_INJECTOR_SET_TARGET_IPV4_VCALL(self, ipv4_addr)  (*(((CordL3StackInjector *)self)->vptr->set_target_ipv4))((self), (ipv4_addr))
#define CORD_L3_STACK_INJECTOR_SET_TARGET_IPV6_VCALL(self, ipv6_addr)  (*(((CordL3StackInjector *)self)->vptr->set_target_ipv6))((self), (ipv6_addr))

#define CORD_L3_STACK_INJECTOR_SET_TARGET_IPV4   CORD_L3_STACK_INJECTOR_SET_TARGET_IPV4_VCALL
#define CORD_L3_STACK_INJECTOR_SET_TARGET_IPV6   CORD_L3_STACK_INJECTOR_SET_TARGET_IPV6_VCALL

static inline void CordL3StackInjector_set_target_ipv4_vcall(CordInjector * const self, in_addr_t ipv4_addr)
{
    (*(((CordL3StackInjector *)self)->vptr->set_target_ipv4))(self, ipv4_addr);
}

static inline void CordL3StackInjector_set_target_ipv6_vcall(CordInjector * const self, struct in6_addr ipv6_addr)
{
    (*(((CordL3StackInjector *)self)->vptr->set_target_ipv6))(self, ipv6_addr);
}

#endif // CORD_L3_STACK_INJECTOR_H
