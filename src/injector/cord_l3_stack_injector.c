#include <injector/cord_l3_stack_injector.h>
#include <cord_error.h>

static cord_retval_t CordL3StackInjector_tx_(CordL3StackInjector const * const self, void *buffer, size_t len, ssize_t *tx_bytes)
{
#ifdef CORD_FLOW_POINT_LOG
    CORD_LOG("[CordL3StackInjector] tx()\n");
#endif
    *tx_bytes = sendto(self->base.io_handle, buffer, len, 0, (struct sockaddr *)&(self->dst_addr_in), sizeof(self->dst_addr_in));
    if (*tx_bytes < 0)
    {
        CORD_ERROR("[CordL3StackInjector] sendto()");
    }

    return CORD_OK;
}

void CordL3StackInjector_set_target_ipv4_(CordL3StackInjector * const self, in_addr_t ipv4_addr)
{
#ifdef CORD_FLOW_POINT_LOG
    CORD_LOG("[CordL3StackInjector] set_target_ipv4()\n");
#endif
    self->dst_addr_in.sin_addr.s_addr = ipv4_addr;
}

void CordL3StackInjector_set_target_ipv6_(CordL3StackInjector * const self, struct in6_addr ipv6_addr)
{
#ifdef CORD_FLOW_POINT_LOG
    CORD_LOG("[CordL3StackInjector] set_target_ipv6()\n");
#endif
    self->dst_addr_in6.sin6_addr = ipv6_addr;
}

void CordL3StackInjector_ctor(CordL3StackInjector * const self,
                                     uint8_t id)
{
#ifdef CORD_FLOW_POINT_LOG
    CORD_LOG("[CordL3StackInjector] ctor()\n");
#endif
    static const CordInjectorVtbl vtbl_base = {
        .tx = (cord_retval_t (*)(CordInjector const * const self, void *buffer, size_t len, ssize_t *tx_bytes))&CordL3StackInjector_tx_,
    };

    static const CordL3StackInjectorVtbl vtbl_deriv = {
        .set_target_ipv4 = (void (*)(CordInjector * const self, in_addr_t ipv4_addr))&CordL3StackInjector_set_target_ipv4_,
        .set_target_ipv6 = (void (*)(CordInjector * const self, struct in6_addr ipv6_addr))&CordL3StackInjector_set_target_ipv6_,
    };

    CordInjector_ctor(&self->base, id);
    self->base.vptr = &vtbl_base;
    self->vptr = &vtbl_deriv;
    self->base.io_handle = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (self->base.io_handle < 0)
    {
        CORD_ERROR("[CordL3StackInjector] socket()");
        CORD_EXIT(EXIT_FAILURE);
    }

    self->ipv4_dst_addr = htonl(INADDR_LOOPBACK);
    inet_pton(AF_INET6, "::1", &(self->ipv6_dst_addr));
    
    self->dst_addr_in.sin_family = AF_INET;
    self->dst_addr_in.sin_addr.s_addr = self->ipv4_dst_addr;

    self->dst_addr_in6.sin6_family = AF_INET6;
    self->dst_addr_in6.sin6_addr = self->ipv6_dst_addr;
    
    int enable = 1;
    if (setsockopt(self->base.io_handle, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0)
    {
        CORD_ERROR("[CordL3StackInjector] setsockopt(IPPROTO_IP, IP_HDRINCL)");
        CORD_EXIT(EXIT_FAILURE);
    }
}

void CordL3StackInjector_dtor(CordL3StackInjector * const self)
{
#ifdef CORD_FLOW_POINT_LOG
    CORD_LOG("[CordL3StackInjector] dtor()\n");
#endif
    close(self->base.io_handle);
    free(self);
}
