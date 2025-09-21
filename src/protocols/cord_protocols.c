/**
 * @file cord_protocols.c
 * @brief Zero-copy protocol header parsing and matching functions
 * 
 * This module provides high-performance, zero-copy protocol header parsing
 * and field matching functions organized by OSI layers. All functions operate 
 * directly on packet buffers without copying data.
 * 
 * Key principles:
 * - Zero-copy: All functions work with pointers to packet data
 * - Portable: Uses our own protocol header definitions
 * - High-performance: Optimized for packet processing pipelines
 * - Type-safe: Uses proper portable types and byte order handling
 * - OSI Layer Organization: Functions are grouped by protocol layer
 */

#include <protocols/cord_protocols.h>

// =============================================================================
// OSI LAYER 2 (DATA LINK) - PROTOCOL HEADER GETTERS
// =============================================================================

// Ethernet Protocol Headers
cord_eth_hdr_t* cord_get_eth_hdr(const void *buffer)
{
    return (cord_eth_hdr_t*)buffer;
}

// VLAN Protocol Headers  
cord_vlan_hdr_t* cord_get_vlan_hdr(const cord_eth_hdr_t *eth_hdr)
{
    uint16_t eth_type = cord_ntohs(eth_hdr->h_proto);
    if (eth_type == CORD_ETH_P_8021Q || eth_type == CORD_ETH_P_8021AD) {
        return (cord_vlan_hdr_t*)((uint8_t*)eth_hdr + sizeof(cord_eth_hdr_t));
    }
    return NULL;
}

// MPLS Protocol Headers
cord_mpls_hdr_t* cord_get_mpls_hdr(const void *buffer, uint16_t offset)
{
    return (cord_mpls_hdr_t*)((uint8_t*)buffer + offset);
}

// ARP Protocol Headers
cord_arp_hdr_t* cord_get_arp_hdr(const cord_eth_hdr_t *eth_hdr)
{
    if (cord_ntohs(eth_hdr->h_proto) != CORD_ETH_P_ARP) {
        return NULL;
    }
    return (cord_arp_hdr_t*)((uint8_t*)eth_hdr + sizeof(cord_eth_hdr_t));
}

// =============================================================================
// OSI LAYER 3 (NETWORK) - PROTOCOL HEADER GETTERS
// =============================================================================

// IPv4 Protocol Headers
cord_ipv4_hdr_t* cord_get_ipv4_hdr(const void *buffer)
{
    return (cord_ipv4_hdr_t*)buffer;
}

cord_ipv4_hdr_t* cord_get_ipv4_hdr_l3(const void *buffer)
{
    return (cord_ipv4_hdr_t*)buffer;
}

cord_ipv4_hdr_t* cord_get_ipv4_hdr_from_eth(const cord_eth_hdr_t *eth_hdr)
{
    if (cord_ntohs(eth_hdr->h_proto) != CORD_ETH_P_IP) {
        return NULL;
    }
    return (cord_ipv4_hdr_t*)((uint8_t*)eth_hdr + sizeof(cord_eth_hdr_t));
}

// IPv6 Protocol Headers
cord_ipv6_hdr_t* cord_get_ipv6_hdr(const void *buffer)
{
    return (cord_ipv6_hdr_t*)buffer;
}

cord_ipv6_hdr_t* cord_get_ipv6_hdr_from_eth(const cord_eth_hdr_t *eth_hdr)
{
    if (cord_ntohs(eth_hdr->h_proto) != CORD_ETH_P_IPV6) {
        return NULL;
    }
    return (cord_ipv6_hdr_t*)((uint8_t*)eth_hdr + sizeof(cord_eth_hdr_t));
}

// ICMP Protocol Headers
cord_icmp_hdr_t* cord_get_icmp_hdr(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_ICMP) {
        return NULL;
    }
    return (cord_icmp_hdr_t*)((uint8_t*)ip_hdr + (CORD_IPV4_GET_IHL(ip_hdr) * 4));
}

cord_icmpv6_hdr_t* cord_get_icmpv6_hdr(const cord_ipv6_hdr_t *ip6_hdr)
{
    if (ip6_hdr->nexthdr != CORD_IPPROTO_ICMPV6) {
        return NULL;
    }
    return (cord_icmpv6_hdr_t*)((uint8_t*)ip6_hdr + sizeof(cord_ipv6_hdr_t));
}

// =============================================================================
// OSI LAYER 4 (TRANSPORT) - PROTOCOL HEADER GETTERS
// =============================================================================

// TCP Protocol Headers
cord_tcp_hdr_t* cord_get_tcp_hdr_ipv4(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_TCP) {
        return NULL;
    }
    return (cord_tcp_hdr_t*)((uint8_t*)ip_hdr + (CORD_IPV4_GET_IHL(ip_hdr) * 4));
}

cord_tcp_hdr_t* cord_get_tcp_hdr_ipv6(const cord_ipv6_hdr_t *ip6_hdr)
{
    if (ip6_hdr->nexthdr != CORD_IPPROTO_TCP) {
        return NULL;
    }
    return (cord_tcp_hdr_t*)((uint8_t*)ip6_hdr + sizeof(cord_ipv6_hdr_t));
}

// UDP Protocol Headers
cord_udp_hdr_t* cord_get_udp_hdr_ipv4(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_UDP) {
        return NULL;
    }
    return (cord_udp_hdr_t*)((uint8_t*)ip_hdr + (CORD_IPV4_GET_IHL(ip_hdr) * 4));
}

cord_udp_hdr_t* cord_get_udp_hdr_ipv6(const cord_ipv6_hdr_t *ip6_hdr)
{
    if (ip6_hdr->nexthdr != CORD_IPPROTO_UDP) {
        return NULL;
    }
    return (cord_udp_hdr_t*)((uint8_t*)ip6_hdr + sizeof(cord_ipv6_hdr_t));
}

// SCTP Protocol Headers
cord_sctp_hdr_t* cord_get_sctp_hdr_ipv4(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_SCTP) {
        return NULL;
    }
    return (cord_sctp_hdr_t*)((uint8_t*)ip_hdr + (CORD_IPV4_GET_IHL(ip_hdr) * 4));
}

cord_sctp_hdr_t* cord_get_sctp_hdr_ipv6(const cord_ipv6_hdr_t *ip6_hdr)
{
    if (ip6_hdr->nexthdr != CORD_IPPROTO_SCTP) {
        return NULL;
    }
    return (cord_sctp_hdr_t*)((uint8_t*)ip6_hdr + sizeof(cord_ipv6_hdr_t));
}

// =============================================================================
// TUNNELING PROTOCOLS - PROTOCOL HEADER GETTERS
// =============================================================================

// GRE Protocol Headers
cord_gre_hdr_t* cord_get_gre_hdr(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_GRE) {
        return NULL;
    }
    return (cord_gre_hdr_t*)((uint8_t*)ip_hdr + (CORD_IPV4_GET_IHL(ip_hdr) * 4));
}

// VXLAN Protocol Headers
cord_vxlan_hdr_t* cord_get_vxlan_hdr(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    if (dst_port != CORD_PORT_VXLAN) {
        return NULL;
    }
    return (cord_vxlan_hdr_t*)((uint8_t*)udp_hdr + sizeof(cord_udp_hdr_t));
}

// GTP-U Protocol Headers
cord_gtpu_hdr_t* cord_get_gtpu_hdr(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    if (dst_port != CORD_PORT_GTPU) {
        return NULL;
    }
    return (cord_gtpu_hdr_t*)((uint8_t*)udp_hdr + sizeof(cord_udp_hdr_t));
}

// =============================================================================
// OSI LAYER 5-7 (SESSION/PRESENTATION/APPLICATION) - PROTOCOL HEADER GETTERS
// =============================================================================

// OSPF Routing Protocol Headers
cord_ospf_hdr_t* cord_get_ospf_hdr(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_OSPF) {
        return NULL;
    }
    return (cord_ospf_hdr_t*)((uint8_t*)ip_hdr + (CORD_IPV4_GET_IHL(ip_hdr) * 4));
}

cord_ospf_hello_t* cord_get_ospf_hello(const cord_ospf_hdr_t *ospf_hdr)
{
    if (ospf_hdr->type != CORD_OSPF_TYPE_HELLO) {
        return NULL;
    }
    return (cord_ospf_hello_t*)ospf_hdr;
}

cord_ospf_db_desc_t* cord_get_ospf_db_desc(const cord_ospf_hdr_t *ospf_hdr)
{
    if (ospf_hdr->type != CORD_OSPF_TYPE_DB_DESC) {
        return NULL;
    }
    return (cord_ospf_db_desc_t*)ospf_hdr;
}

cord_ospf_ls_req_t* cord_get_ospf_ls_req(const cord_ospf_hdr_t *ospf_hdr)
{
    if (ospf_hdr->type != CORD_OSPF_TYPE_LS_REQ) {
        return NULL;
    }
    return (cord_ospf_ls_req_t*)ospf_hdr;
}

cord_ospf_ls_upd_t* cord_get_ospf_ls_upd(const cord_ospf_hdr_t *ospf_hdr)
{
    if (ospf_hdr->type != CORD_OSPF_TYPE_LS_UPD) {
        return NULL;
    }
    return (cord_ospf_ls_upd_t*)ospf_hdr;
}

cord_ospf_ls_ack_t* cord_get_ospf_ls_ack(const cord_ospf_hdr_t *ospf_hdr)
{
    if (ospf_hdr->type != CORD_OSPF_TYPE_LS_ACK) {
        return NULL;
    }
    return (cord_ospf_ls_ack_t*)ospf_hdr;
}

cord_ospf_lsa_hdr_t* cord_get_ospf_lsa_hdr(const void *lsa_data)
{
    return (cord_ospf_lsa_hdr_t*)lsa_data;
}

cord_ospf_router_lsa_t* cord_get_ospf_router_lsa(const cord_ospf_lsa_hdr_t *lsa_hdr)
{
    if (lsa_hdr->ls_type != CORD_OSPF_LSA_ROUTER) {
        return NULL;
    }
    return (cord_ospf_router_lsa_t*)lsa_hdr;
}

cord_ospf_network_lsa_t* cord_get_ospf_network_lsa(const cord_ospf_lsa_hdr_t *lsa_hdr)
{
    if (lsa_hdr->ls_type != CORD_OSPF_LSA_NETWORK) {
        return NULL;
    }
    return (cord_ospf_network_lsa_t*)lsa_hdr;
}

cord_ospf_summary_lsa_t* cord_get_ospf_summary_lsa(const cord_ospf_lsa_hdr_t *lsa_hdr)
{
    if (lsa_hdr->ls_type != CORD_OSPF_LSA_SUMMARY_NET && 
        lsa_hdr->ls_type != CORD_OSPF_LSA_SUMMARY_ASBR) {
        return NULL;
    }
    return (cord_ospf_summary_lsa_t*)lsa_hdr;
}

cord_ospf_external_lsa_t* cord_get_ospf_external_lsa(const cord_ospf_lsa_hdr_t *lsa_hdr)
{
    if (lsa_hdr->ls_type != CORD_OSPF_LSA_EXTERNAL) {
        return NULL;
    }
    return (cord_ospf_external_lsa_t*)lsa_hdr;
}

cord_ospf_nssa_lsa_t* cord_get_ospf_nssa_lsa(const cord_ospf_lsa_hdr_t *lsa_hdr)
{
    if (lsa_hdr->ls_type != CORD_OSPF_LSA_NSSA) {
        return NULL;
    }
    return (cord_ospf_nssa_lsa_t*)lsa_hdr;
}

cord_ospf_opaque_lsa_t* cord_get_ospf_opaque_lsa(const cord_ospf_lsa_hdr_t *lsa_hdr)
{
    if (lsa_hdr->ls_type != CORD_OSPF_LSA_LINK_LOCAL &&
        lsa_hdr->ls_type != CORD_OSPF_LSA_AREA_LOCAL &&
        lsa_hdr->ls_type != CORD_OSPF_LSA_AS_EXTERNAL) {
        return NULL;
    }
    return (cord_ospf_opaque_lsa_t*)lsa_hdr;
}

// BGP Routing Protocol Headers
cord_bgp_hdr_t* cord_get_bgp_hdr(const cord_tcp_hdr_t *tcp_hdr)
{
    uint16_t src_port = cord_ntohs(tcp_hdr->source);
    uint16_t dst_port = cord_ntohs(tcp_hdr->dest);
    
    if (src_port != CORD_PORT_BGP && dst_port != CORD_PORT_BGP) {
        return NULL;
    }
    
    // Get the BGP header - it starts after the TCP header
    return (cord_bgp_hdr_t*)((uint8_t*)tcp_hdr + (CORD_TCP_GET_DOFF(tcp_hdr) * 4));
}

cord_bgp_open_t* cord_get_bgp_open(const cord_bgp_hdr_t *bgp_hdr)
{
    if (bgp_hdr->type != CORD_BGP_TYPE_OPEN) {
        return NULL;
    }
    return (cord_bgp_open_t*)bgp_hdr;
}

cord_bgp_update_t* cord_get_bgp_update(const cord_bgp_hdr_t *bgp_hdr)
{
    if (bgp_hdr->type != CORD_BGP_TYPE_UPDATE) {
        return NULL;
    }
    return (cord_bgp_update_t*)bgp_hdr;
}

cord_bgp_notification_t* cord_get_bgp_notification(const cord_bgp_hdr_t *bgp_hdr)
{
    if (bgp_hdr->type != CORD_BGP_TYPE_NOTIFICATION) {
        return NULL;
    }
    return (cord_bgp_notification_t*)bgp_hdr;
}

cord_bgp_keepalive_t* cord_get_bgp_keepalive(const cord_bgp_hdr_t *bgp_hdr)
{
    if (bgp_hdr->type != CORD_BGP_TYPE_KEEPALIVE) {
        return NULL;
    }
    return (cord_bgp_keepalive_t*)bgp_hdr;
}

cord_bgp_path_attr_t* cord_get_bgp_path_attr(const void *attr_data)
{
    return (cord_bgp_path_attr_t*)attr_data;
}

cord_bgp_origin_attr_t* cord_get_bgp_origin_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_ORIGIN) {
        return NULL;
    }
    return (cord_bgp_origin_attr_t*)attr;
}

cord_bgp_as_path_attr_t* cord_get_bgp_as_path_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_AS_PATH) {
        return NULL;
    }
    return (cord_bgp_as_path_attr_t*)attr;
}

cord_bgp_next_hop_attr_t* cord_get_bgp_next_hop_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_NEXT_HOP) {
        return NULL;
    }
    return (cord_bgp_next_hop_attr_t*)attr;
}

cord_bgp_med_attr_t* cord_get_bgp_med_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_MED) {
        return NULL;
    }
    return (cord_bgp_med_attr_t*)attr;
}

cord_bgp_local_pref_attr_t* cord_get_bgp_local_pref_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_LOCAL_PREF) {
        return NULL;
    }
    return (cord_bgp_local_pref_attr_t*)attr;
}

cord_bgp_communities_attr_t* cord_get_bgp_communities_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_COMMUNITIES) {
        return NULL;
    }
    return (cord_bgp_communities_attr_t*)attr;
}

cord_bgp_mp_reach_attr_t* cord_get_bgp_mp_reach_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_MP_REACH_NLRI) {
        return NULL;
    }
    return (cord_bgp_mp_reach_attr_t*)attr;
}

cord_bgp_mp_unreach_attr_t* cord_get_bgp_mp_unreach_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_MP_UNREACH_NLRI) {
        return NULL;
    }
    return (cord_bgp_mp_unreach_attr_t*)attr;
}

cord_bgp_extended_communities_attr_t* cord_get_bgp_extended_communities_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_EXT_COMMUNITIES) {
        return NULL;
    }
    return (cord_bgp_extended_communities_attr_t*)attr;
}

cord_bgp_large_communities_attr_t* cord_get_bgp_large_communities_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_LARGE_COMM) {
        return NULL;
    }
    return (cord_bgp_large_communities_attr_t*)attr;
}

// RIP Routing Protocol Headers
cord_rip_hdr_t* cord_get_rip_hdr(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t src_port = cord_ntohs(udp_hdr->source);
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    
    if (src_port != CORD_PORT_RIP && dst_port != CORD_PORT_RIP) {
        return NULL;
    }
    
    return (cord_rip_hdr_t*)((uint8_t*)udp_hdr + sizeof(cord_udp_hdr_t));
}

cord_rip_msg_t* cord_get_rip_msg(const cord_udp_hdr_t *udp_hdr)
{
    return (cord_rip_msg_t*)((uint8_t*)udp_hdr + sizeof(cord_udp_hdr_t));
}

cord_rip_v1_entry_t* cord_get_rip_v1_entry(const cord_rip_msg_t *rip_msg, uint16_t index)
{
    if (index >= 25) {
        return NULL;
    }
    
    // For RIP v1, all entries are v1 format
    return (cord_rip_v1_entry_t*)((uint8_t*)rip_msg + sizeof(cord_rip_msg_t) + 
                                  index * sizeof(cord_rip_v1_entry_t));
}

cord_rip_v2_entry_t* cord_get_rip_v2_entry(const cord_rip_msg_t *rip_msg, uint16_t index)
{
    if (index >= 25) {
        return NULL;
    }
    
    // For RIP v2, entries can be route entries or authentication entries
    cord_rip_v2_entry_t *entry = (cord_rip_v2_entry_t*)((uint8_t*)rip_msg + sizeof(cord_rip_msg_t) + 
                                                        index * sizeof(cord_rip_v2_entry_t));
    
    // Skip authentication entries
    if (cord_ntohs(entry->address_family) == CORD_RIP_AF_AUTH) {
        return NULL;
    }
    
    return entry;
}

cord_rip_v2_auth_t* cord_get_rip_v2_auth(const cord_rip_msg_t *rip_msg, uint16_t index)
{
    if (index >= 25) {
        return NULL;
    }
    
    cord_rip_v2_entry_t *entry = (cord_rip_v2_entry_t*)((uint8_t*)rip_msg + sizeof(cord_rip_msg_t) + 
                                                        index * sizeof(cord_rip_v2_entry_t));
    
    // Only return authentication entries
    if (cord_ntohs(entry->address_family) != CORD_RIP_AF_AUTH) {
        return NULL;
    }
    
    return (cord_rip_v2_auth_t*)entry;
}

cord_ripng_hdr_t* cord_get_ripng_hdr(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t src_port = cord_ntohs(udp_hdr->source);
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    
    if (src_port != CORD_PORT_RIPNG && dst_port != CORD_PORT_RIPNG) {
        return NULL;
    }
    
    return (cord_ripng_hdr_t*)((uint8_t*)udp_hdr + sizeof(cord_udp_hdr_t));
}

cord_ripng_entry_t* cord_get_ripng_entry(const cord_ripng_hdr_t *ripng_hdr, uint16_t index)
{
    if (index >= 25) {
        return NULL;
    }
    
    return (cord_ripng_entry_t*)((uint8_t*)ripng_hdr + sizeof(cord_ripng_hdr_t) + 
                                 index * sizeof(cord_ripng_entry_t));
}

// IS-IS Routing Protocol Headers
cord_isis_common_hdr_t* cord_get_isis_common_hdr(const void *buffer)
{
    cord_isis_common_hdr_t *hdr = (cord_isis_common_hdr_t*)buffer;
    
    // Basic validation
    if (hdr->irpd != CORD_ISIS_PROTO_DISCRIMINATOR) {
        return NULL;
    }
    
    return hdr;
}

cord_isis_p2p_hello_t* cord_get_isis_p2p_hello(const cord_isis_common_hdr_t *common_hdr)
{
    if (common_hdr->pdu_type != CORD_ISIS_PDU_PTP_IIH) {
        return NULL;
    }
    return (cord_isis_p2p_hello_t*)common_hdr;
}

cord_isis_lan_hello_t* cord_get_isis_lan_hello(const cord_isis_common_hdr_t *common_hdr)
{
    if (common_hdr->pdu_type != CORD_ISIS_PDU_L1_LAN_IIH &&
        common_hdr->pdu_type != CORD_ISIS_PDU_L2_LAN_IIH) {
        return NULL;
    }
    return (cord_isis_lan_hello_t*)common_hdr;
}

cord_isis_lsp_t* cord_get_isis_lsp(const cord_isis_common_hdr_t *common_hdr)
{
    if (common_hdr->pdu_type != CORD_ISIS_PDU_L1_LSP &&
        common_hdr->pdu_type != CORD_ISIS_PDU_L2_LSP) {
        return NULL;
    }
    return (cord_isis_lsp_t*)common_hdr;
}

cord_isis_csnp_t* cord_get_isis_csnp(const cord_isis_common_hdr_t *common_hdr)
{
    if (common_hdr->pdu_type != CORD_ISIS_PDU_L1_CSNP &&
        common_hdr->pdu_type != CORD_ISIS_PDU_L2_CSNP) {
        return NULL;
    }
    return (cord_isis_csnp_t*)common_hdr;
}

cord_isis_psnp_t* cord_get_isis_psnp(const cord_isis_common_hdr_t *common_hdr)
{
    if (common_hdr->pdu_type != CORD_ISIS_PDU_L1_PSNP &&
        common_hdr->pdu_type != CORD_ISIS_PDU_L2_PSNP) {
        return NULL;
    }
    return (cord_isis_psnp_t*)common_hdr;
}

cord_isis_tlv_t* cord_get_isis_tlv(const void *tlv_data)
{
    return (cord_isis_tlv_t*)tlv_data;
}

cord_isis_area_addr_tlv_t* cord_get_isis_area_addr_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_AREA_ADDR) {
        return NULL;
    }
    return (cord_isis_area_addr_tlv_t*)tlv;
}

cord_isis_iis_neighbors_tlv_t* cord_get_isis_iis_neighbors_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_IIS_NEIGHBORS) {
        return NULL;
    }
    return (cord_isis_iis_neighbors_tlv_t*)tlv;
}

cord_isis_auth_tlv_t* cord_get_isis_auth_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_AUTHENTICATION) {
        return NULL;
    }
    return (cord_isis_auth_tlv_t*)tlv;
}

cord_isis_lsp_entries_tlv_t* cord_get_isis_lsp_entries_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_LSP_ENTRIES) {
        return NULL;
    }
    return (cord_isis_lsp_entries_tlv_t*)tlv;
}

cord_isis_extended_is_reach_tlv_t* cord_get_isis_extended_is_reach_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_EXTENDED_IS_REACH) {
        return NULL;
    }
    return (cord_isis_extended_is_reach_tlv_t*)tlv;
}

cord_isis_ip_internal_reach_tlv_t* cord_get_isis_ip_internal_reach_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_IP_INTERNAL_REACH) {
        return NULL;
    }
    return (cord_isis_ip_internal_reach_tlv_t*)tlv;
}

cord_isis_ip_external_reach_tlv_t* cord_get_isis_ip_external_reach_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_IP_EXTERNAL_REACH) {
        return NULL;
    }
    return (cord_isis_ip_external_reach_tlv_t*)tlv;
}

cord_isis_extended_ip_reach_tlv_t* cord_get_isis_extended_ip_reach_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_EXTENDED_IP_REACH) {
        return NULL;
    }
    return (cord_isis_extended_ip_reach_tlv_t*)tlv;
}

cord_isis_ipv6_reach_tlv_t* cord_get_isis_ipv6_reach_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_IPV6_REACH) {
        return NULL;
    }
    return (cord_isis_ipv6_reach_tlv_t*)tlv;
}

// EIGRP Routing Protocol Headers
cord_eigrp_hdr_t* cord_get_eigrp_hdr(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_EIGRP) {
        return NULL;
    }
    return (cord_eigrp_hdr_t*)((uint8_t*)ip_hdr + (CORD_IPV4_GET_IHL(ip_hdr) * 4));
}

cord_eigrp_tlv_t* cord_get_eigrp_tlv(const void *tlv_data)
{
    return (cord_eigrp_tlv_t*)tlv_data;
}

// PIM Multicast Protocol Headers
cord_pim_hdr_t* cord_get_pim_hdr(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_PORT_PIM) {
        return NULL;
    }
    return (cord_pim_hdr_t*)((uint8_t*)ip_hdr + (CORD_IPV4_GET_IHL(ip_hdr) * 4));
}

// IGMP Multicast Protocol Headers
cord_igmpv3_query_t* cord_get_igmpv3_query(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_IGMP) {
        return NULL;
    }
    
    // Get the IGMP header
    cord_igmp_hdr_t *igmp = (cord_igmp_hdr_t*)((uint8_t*)ip_hdr + (CORD_IPV4_GET_IHL(ip_hdr) * 4));
    
    // Check if it's an IGMPv3 query
    if (igmp->type != CORD_IGMP_TYPE_MEMBERSHIP_QUERY) {
        return NULL;
    }
    
    return (cord_igmpv3_query_t*)igmp;
}

// First Hop Redundancy Protocol Headers
cord_hsrp_hdr_t* cord_get_hsrp_hdr(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t src_port = cord_ntohs(udp_hdr->source);
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    
    if (src_port != CORD_PORT_HSRP && dst_port != CORD_PORT_HSRP) {
        return NULL;
    }
    
    return (cord_hsrp_hdr_t*)((uint8_t*)udp_hdr + sizeof(cord_udp_hdr_t));
}

cord_vrrp_hdr_t* cord_get_vrrp_hdr(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_PORT_VRRP) {
        return NULL;
    }
    return (cord_vrrp_hdr_t*)((uint8_t*)ip_hdr + (CORD_IPV4_GET_IHL(ip_hdr) * 4));
}

// Network Management Protocol Headers
cord_bfd_hdr_t* cord_get_bfd_hdr(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t src_port = cord_ntohs(udp_hdr->source);
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    
    if (src_port != CORD_PORT_BFD_CONTROL && dst_port != CORD_PORT_BFD_CONTROL &&
        src_port != CORD_PORT_BFD_ECHO && dst_port != CORD_PORT_BFD_ECHO) {
        return NULL;
    }
    
    return (cord_bfd_hdr_t*)((uint8_t*)udp_hdr + sizeof(cord_udp_hdr_t));
}

cord_ldp_hdr_t* cord_get_ldp_hdr(const cord_tcp_hdr_t *tcp_hdr)
{
    uint16_t src_port = cord_ntohs(tcp_hdr->source);
    uint16_t dst_port = cord_ntohs(tcp_hdr->dest);
    
    if (src_port != CORD_PORT_LDP && dst_port != CORD_PORT_LDP) {
        return NULL;
    }
    
    return (cord_ldp_hdr_t*)((uint8_t*)tcp_hdr + (CORD_TCP_GET_DOFF(tcp_hdr) * 4));
}

cord_rsvp_hdr_t* cord_get_rsvp_hdr(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_PORT_RSVP) {
        return NULL;
    }
    return (cord_rsvp_hdr_t*)((uint8_t*)ip_hdr + (CORD_IPV4_GET_IHL(ip_hdr) * 4));
}

// DHCP Protocol Headers
cord_dhcp_hdr_t* cord_get_dhcp_hdr(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t src_port = cord_ntohs(udp_hdr->source);
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    
    if (!((src_port == CORD_PORT_DHCP_SERVER && dst_port == CORD_PORT_DHCP_CLIENT) ||
          (src_port == CORD_PORT_DHCP_CLIENT && dst_port == CORD_PORT_DHCP_SERVER))) {
        return NULL;
    }
    
    return (cord_dhcp_hdr_t*)((uint8_t*)udp_hdr + sizeof(cord_udp_hdr_t));
}

cord_dhcp_option_t* cord_get_dhcp_option(const cord_dhcp_hdr_t *dhcp_hdr, uint16_t offset)
{
    // DHCP options start after the fixed header and magic cookie
    uint8_t *options_start = (uint8_t*)dhcp_hdr + sizeof(cord_dhcp_hdr_t) + 4; // +4 for magic cookie
    
    return (cord_dhcp_option_t*)(options_start + offset);
}

cord_dhcpv6_hdr_t* cord_get_dhcpv6_hdr(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t src_port = cord_ntohs(udp_hdr->source);
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    
    if (!((src_port == CORD_PORT_DHCPV6_SERVER && dst_port == CORD_PORT_DHCPV6_CLIENT) ||
          (src_port == CORD_PORT_DHCPV6_CLIENT && dst_port == CORD_PORT_DHCPV6_SERVER))) {
        return NULL;
    }
    
    return (cord_dhcpv6_hdr_t*)((uint8_t*)udp_hdr + sizeof(cord_udp_hdr_t));
}

cord_dhcpv6_relay_hdr_t* cord_get_dhcpv6_relay_hdr(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t src_port = cord_ntohs(udp_hdr->source);
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    
    if (!((src_port == CORD_PORT_DHCPV6_SERVER && dst_port == CORD_PORT_DHCPV6_CLIENT) ||
          (src_port == CORD_PORT_DHCPV6_CLIENT && dst_port == CORD_PORT_DHCPV6_SERVER))) {
        return NULL;
    }
    
    return (cord_dhcpv6_relay_hdr_t*)((uint8_t*)udp_hdr + sizeof(cord_udp_hdr_t));
}

cord_dhcpv6_option_t* cord_get_dhcpv6_option(const void *options_data, uint16_t offset)
{
    return (cord_dhcpv6_option_t*)((uint8_t*)options_data + offset);
}

// IPv6 Neighbor Discovery Protocol Headers
cord_ipv6_nd_router_solicit_t* cord_get_ipv6_nd_router_solicit(const cord_icmpv6_hdr_t *icmp6_hdr)
{
    if (icmp6_hdr->type != CORD_ICMPV6_ND_ROUTER_SOLICIT) {
        return NULL;
    }
    return (cord_ipv6_nd_router_solicit_t*)icmp6_hdr;
}

cord_ipv6_nd_router_advert_t* cord_get_ipv6_nd_router_advert(const cord_icmpv6_hdr_t *icmp6_hdr)
{
    if (icmp6_hdr->type != CORD_ICMPV6_ND_ROUTER_ADVERT) {
        return NULL;
    }
    return (cord_ipv6_nd_router_advert_t*)icmp6_hdr;
}

cord_ipv6_nd_neighbor_solicit_t* cord_get_ipv6_nd_neighbor_solicit(const cord_icmpv6_hdr_t *icmp6_hdr)
{
    if (icmp6_hdr->type != CORD_ICMPV6_ND_NEIGHBOR_SOLICIT) {
        return NULL;
    }
    return (cord_ipv6_nd_neighbor_solicit_t*)icmp6_hdr;
}

cord_ipv6_nd_neighbor_advert_t* cord_get_ipv6_nd_neighbor_advert(const cord_icmpv6_hdr_t *icmp6_hdr)
{
    if (icmp6_hdr->type != CORD_ICMPV6_ND_NEIGHBOR_ADVERT) {
        return NULL;
    }
    return (cord_ipv6_nd_neighbor_advert_t*)icmp6_hdr;
}

cord_ipv6_nd_redirect_t* cord_get_ipv6_nd_redirect(const cord_icmpv6_hdr_t *icmp6_hdr)
{
    if (icmp6_hdr->type != CORD_ICMPV6_ND_REDIRECT) {
        return NULL;
    }
    return (cord_ipv6_nd_redirect_t*)icmp6_hdr;
}

cord_ipv6_nd_opt_t* cord_get_ipv6_nd_option(const void *options_data, uint16_t offset)
{
    return (cord_ipv6_nd_opt_t*)((uint8_t*)options_data + offset);
}

cord_ipv6_nd_opt_lladdr_t* cord_get_ipv6_nd_opt_lladdr(const cord_ipv6_nd_opt_t *opt)
{
    if (opt->type != CORD_IPV6_ND_OPT_SOURCE_LLADDR && 
        opt->type != CORD_IPV6_ND_OPT_TARGET_LLADDR) {
        return NULL;
    }
    return (cord_ipv6_nd_opt_lladdr_t*)((uint8_t*)opt + sizeof(cord_ipv6_nd_opt_t));
}

cord_ipv6_nd_opt_prefix_info_t* cord_get_ipv6_nd_opt_prefix_info(const cord_ipv6_nd_opt_t *opt)
{
    if (opt->type != CORD_IPV6_ND_OPT_PREFIX_INFO) {
        return NULL;
    }
    return (cord_ipv6_nd_opt_prefix_info_t*)((uint8_t*)opt + sizeof(cord_ipv6_nd_opt_t));
}

cord_ipv6_nd_opt_mtu_t* cord_get_ipv6_nd_opt_mtu(const cord_ipv6_nd_opt_t *opt)
{
    if (opt->type != CORD_IPV6_ND_OPT_MTU) {
        return NULL;
    }
    return (cord_ipv6_nd_opt_mtu_t*)((uint8_t*)opt + sizeof(cord_ipv6_nd_opt_t));
}

cord_ipv6_nd_opt_rdnss_t* cord_get_ipv6_nd_opt_rdnss(const cord_ipv6_nd_opt_t *opt)
{
    if (opt->type != CORD_IPV6_ND_OPT_RDNSS) {
        return NULL;
    }
    return (cord_ipv6_nd_opt_rdnss_t*)((uint8_t*)opt + sizeof(cord_ipv6_nd_opt_t));
}

cord_ipv6_nd_opt_dnssl_t* cord_get_ipv6_nd_opt_dnssl(const cord_ipv6_nd_opt_t *opt)
{
    if (opt->type != CORD_IPV6_ND_OPT_DNSSL) {
        return NULL;
    }
    return (cord_ipv6_nd_opt_dnssl_t*)((uint8_t*)opt + sizeof(cord_ipv6_nd_opt_t));
}

// =============================================================================
// OSI LAYER 2 (DATA LINK) - PROTOCOL FIELD GETTERS
// =============================================================================

// Ethernet Field Getters
void cord_get_eth_dst_addr(const cord_eth_hdr_t *eth, cord_mac_addr_t *dst)
{
    *dst = eth->h_dest;
}

void cord_get_eth_src_addr(const cord_eth_hdr_t *eth, cord_mac_addr_t *src)
{
    *src = eth->h_source;
}

uint16_t cord_get_eth_type(const cord_eth_hdr_t *eth)
{
    return cord_ntohs(eth->h_proto);
}

// VLAN Field Getters
uint8_t cord_get_vlan_pcp(const cord_vlan_hdr_t *vlan)
{
    return (cord_ntohs(vlan->tci) >> 13) & 0x07;
}

uint8_t cord_get_vlan_dei(const cord_vlan_hdr_t *vlan)
{
    return (cord_ntohs(vlan->tci) >> 12) & 0x01;
}

uint16_t cord_get_vlan_vid(const cord_vlan_hdr_t *vlan)
{
    return cord_ntohs(vlan->tci) & 0x0FFF;
}

// =============================================================================
// OSI LAYER 3 (NETWORK) - PROTOCOL FIELD GETTERS
// =============================================================================

// IPv4 Field Getters
uint8_t cord_get_ipv4_version(const cord_ipv4_hdr_t *ip)
{
    return ip->version;
}

uint8_t cord_get_ipv4_ihl(const cord_ipv4_hdr_t *ip)
{
    return ip->ihl;
}

uint8_t cord_get_ipv4_tos(const cord_ipv4_hdr_t *ip)
{
    return ip->tos;
}

uint8_t cord_get_ipv4_dscp(const cord_ipv4_hdr_t *ip)
{
    return (ip->tos >> 2) & 0x3F;
}

uint8_t cord_get_ipv4_ecn(const cord_ipv4_hdr_t *ip)
{
    return ip->tos & 0x03;
}

uint16_t cord_get_ipv4_total_length(const cord_ipv4_hdr_t *ip)
{
    return ip->tot_len;
}

uint16_t cord_get_ipv4_id(const cord_ipv4_hdr_t *ip)
{
    return ip->id;
}

uint16_t cord_get_ipv4_frag_off(const cord_ipv4_hdr_t *ip)
{
    return ip->frag_off;
}

uint8_t cord_get_ipv4_ttl(const cord_ipv4_hdr_t *ip)
{
    return ip->ttl;
}

uint8_t cord_get_ipv4_protocol(const cord_ipv4_hdr_t *ip)
{
    return ip->protocol;
}

uint16_t cord_get_ipv4_checksum(const cord_ipv4_hdr_t *ip)
{
    return ip->check;
}

uint32_t cord_get_ipv4_src_addr(const cord_ipv4_hdr_t *ip)
{
    return ip->saddr.addr;
}

uint32_t cord_get_ipv4_dst_addr(const cord_ipv4_hdr_t *ip)
{
    return ip->daddr.addr;
}

uint16_t cord_get_ipv4_total_length_ntohs(const cord_ipv4_hdr_t *ip)
{
    return cord_ntohs(ip->tot_len);
}

uint8_t cord_get_ipv4_header_length(const cord_ipv4_hdr_t *ip)
{
    return (ip->ihl) * 4;
}

uint32_t cord_get_ipv4_src_addr_ntohl(const cord_ipv4_hdr_t *ip)
{
    return cord_ntohl(ip->saddr.addr);
}

uint32_t cord_get_ipv4_dst_addr_ntohl(const cord_ipv4_hdr_t *ip)
{
    return cord_ntohl(ip->daddr.addr);
}

uint32_t cord_get_ipv4_src_addr_l3(const cord_ipv4_hdr_t *ip)
{
    return ip->saddr.addr;
}

uint32_t cord_get_ipv4_dst_addr_l3(const cord_ipv4_hdr_t *ip)
{
    return ip->daddr.addr;
}

// IPv6 Field Getters
uint8_t cord_get_ipv6_version(const cord_ipv6_hdr_t *ip6)
{
    return ip6->version;
}

uint8_t cord_get_ipv6_traffic_class(const cord_ipv6_hdr_t *ip6)
{
    return ip6->traffic_class;
}

uint32_t cord_get_ipv6_flow_label(const cord_ipv6_hdr_t *ip6)
{
    return ip6->flow_label;
}

uint16_t cord_get_ipv6_payload_length(const cord_ipv6_hdr_t *ip6)
{
    return cord_ntohs(ip6->payload_len);
}

uint8_t cord_get_ipv6_next_header(const cord_ipv6_hdr_t *ip6)
{
    return ip6->nexthdr;
}

uint8_t cord_get_ipv6_hop_limit(const cord_ipv6_hdr_t *ip6)
{
    return ip6->hop_limit;
}

void cord_get_ipv6_src_addr(const cord_ipv6_hdr_t *ip6, cord_ipv6_addr_t *src)
{
    *src = ip6->saddr;
}

void cord_get_ipv6_dst_addr(const cord_ipv6_hdr_t *ip6, cord_ipv6_addr_t *dst)
{
    *dst = ip6->daddr;
}

// ICMP Field Getters
uint8_t cord_get_icmp_type(const cord_icmp_hdr_t *icmp)
{
    return icmp->type;
}

uint8_t cord_get_icmp_code(const cord_icmp_hdr_t *icmp)
{
    return icmp->code;
}

uint16_t cord_get_icmp_checksum(const cord_icmp_hdr_t *icmp)
{
    return icmp->checksum;
}

uint16_t cord_get_icmp_id(const cord_icmp_hdr_t *icmp)
{
    return cord_ntohs(icmp->un.echo.id);
}

uint16_t cord_get_icmp_sequence(const cord_icmp_hdr_t *icmp)
{
    return cord_ntohs(icmp->un.echo.sequence);
}

// =============================================================================
// OSI LAYER 4 (TRANSPORT) - PROTOCOL FIELD GETTERS
// =============================================================================

// TCP Field Getters
uint16_t cord_get_tcp_src_port(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohs(tcp->source);
}

uint16_t cord_get_tcp_dst_port(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohs(tcp->dest);
}

uint32_t cord_get_tcp_seq_num(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohl(tcp->seq);
}

uint32_t cord_get_tcp_ack_num(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohl(tcp->ack_seq);
}

uint8_t cord_get_tcp_doff(const cord_tcp_hdr_t *tcp)
{
    return tcp->doff;
}

uint16_t cord_get_tcp_window(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohs(tcp->window);
}

uint16_t cord_get_tcp_checksum(const cord_tcp_hdr_t *tcp)
{
    return tcp->check;
}

uint16_t cord_get_tcp_urgent_ptr(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohs(tcp->urg_ptr);
}

bool cord_get_tcp_fin(const cord_tcp_hdr_t *tcp)
{
    return tcp->fin;
}

bool cord_get_tcp_syn(const cord_tcp_hdr_t *tcp)
{
    return tcp->syn;
}

bool cord_get_tcp_rst(const cord_tcp_hdr_t *tcp)
{
    return tcp->rst;
}

bool cord_get_tcp_psh(const cord_tcp_hdr_t *tcp)
{
    return tcp->psh;
}

bool cord_get_tcp_ack(const cord_tcp_hdr_t *tcp)
{
    return tcp->ack;
}

bool cord_get_tcp_urg(const cord_tcp_hdr_t *tcp)
{
    return tcp->urg;
}

bool cord_get_tcp_ece(const cord_tcp_hdr_t *tcp)
{
    return tcp->ece;
}

bool cord_get_tcp_cwr(const cord_tcp_hdr_t *tcp)
{
    return tcp->cwr;
}

// UDP Field Getters
uint16_t cord_get_udp_src_port(const cord_udp_hdr_t *udp)
{
    return cord_ntohs(udp->source);
}

uint16_t cord_get_udp_dst_port(const cord_udp_hdr_t *udp)
{
    return cord_ntohs(udp->dest);
}

uint16_t cord_get_udp_length(const cord_udp_hdr_t *udp)
{
    return cord_ntohs(udp->len);
}

uint16_t cord_get_udp_checksum(const cord_udp_hdr_t *udp)
{
    return udp->check;
}

// SCTP Field Getters
uint16_t cord_get_sctp_src_port(const cord_sctp_hdr_t *sctp)
{
    return cord_ntohs(sctp->source);
}

uint16_t cord_get_sctp_dst_port(const cord_sctp_hdr_t *sctp)
{
    return cord_ntohs(sctp->dest);
}

uint32_t cord_get_sctp_vtag(const cord_sctp_hdr_t *sctp)
{
    return cord_ntohl(sctp->vtag);
}

uint32_t cord_get_sctp_checksum(const cord_sctp_hdr_t *sctp)
{
    return sctp->checksum;
}

// =============================================================================
// OSI LAYER 2 (DATA LINK) - PROTOCOL FIELD MATCHING FUNCTIONS
// =============================================================================

// Ethernet Match Functions
bool cord_match_eth_dst_addr(const cord_eth_hdr_t *eth, const cord_mac_addr_t *addr)
{
    for (int i = 0; i < 6; i++) {
        if (eth->h_dest.addr[i] != addr->addr[i]) {
            return false;
        }
    }
    return true;
}

bool cord_match_eth_src_addr(const cord_eth_hdr_t *eth, const cord_mac_addr_t *addr)
{
    for (int i = 0; i < 6; i++) {
        if (eth->h_source.addr[i] != addr->addr[i]) {
            return false;
        }
    }
    return true;
}

bool cord_match_eth_type(const cord_eth_hdr_t *eth, uint16_t eth_type)
{
    return cord_ntohs(eth->h_proto) == eth_type;
}

bool cord_match_eth_broadcast(const cord_eth_hdr_t *eth)
{
    static const uint8_t broadcast_addr[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return memcmp(&eth->h_dest, broadcast_addr, 6) == 0;
}

bool cord_match_eth_multicast(const cord_eth_hdr_t *eth)
{
    return (eth->h_dest.addr[0] & 0x01) != 0;
}

bool cord_match_eth_unicast(const cord_eth_hdr_t *eth)
{
    return (eth->h_dest.addr[0] & 0x01) == 0;
}

// VLAN Match Functions
bool cord_match_vlan_pcp(const cord_vlan_hdr_t *vlan, uint8_t pcp)
{
    return cord_get_vlan_pcp(vlan) == pcp;
}

bool cord_match_vlan_dei(const cord_vlan_hdr_t *vlan, uint8_t dei)
{
    return cord_get_vlan_dei(vlan) == dei;
}

bool cord_match_vlan_vid(const cord_vlan_hdr_t *vlan, uint16_t vid)
{
    return cord_get_vlan_vid(vlan) == vid;
}

bool cord_match_vlan_vid_range(const cord_vlan_hdr_t *vlan, uint16_t min_vid, uint16_t max_vid)
{
    uint16_t vid = cord_get_vlan_vid(vlan);
    return vid >= min_vid && vid <= max_vid;
}

// =============================================================================
// OSI LAYER 3 (NETWORK) - PROTOCOL FIELD MATCHING FUNCTIONS
// =============================================================================

// IPv4 Match Functions
bool cord_match_ipv4_version(const cord_ipv4_hdr_t *ip)
{
    return cord_get_ipv4_version(ip) == 4;
}

bool cord_match_ipv4_ihl(const cord_ipv4_hdr_t *ip, uint8_t ihl)
{
    return cord_get_ipv4_ihl(ip) == ihl;
}

bool cord_match_ipv4_tos(const cord_ipv4_hdr_t *ip, uint8_t tos)
{
    return cord_get_ipv4_tos(ip) == tos;
}

bool cord_match_ipv4_dscp(const cord_ipv4_hdr_t *ip, uint8_t dscp)
{
    return cord_get_ipv4_dscp(ip) == dscp;
}

bool cord_match_ipv4_ecn(const cord_ipv4_hdr_t *ip, uint8_t ecn)
{
    return cord_get_ipv4_ecn(ip) == ecn;
}

bool cord_match_ipv4_total_length(const cord_ipv4_hdr_t *ip, uint16_t length)
{
    return cord_ntohs(ip->tot_len) == length;
}

bool cord_match_ipv4_id(const cord_ipv4_hdr_t *ip, uint16_t id)
{
    return cord_ntohs(ip->id) == id;
}

bool cord_match_ipv4_flags(const cord_ipv4_hdr_t *ip, uint16_t flags)
{
    return (cord_ntohs(ip->frag_off) >> 13) == flags;
}

bool cord_match_ipv4_frag_offset(const cord_ipv4_hdr_t *ip, uint16_t offset)
{
    return (cord_ntohs(ip->frag_off) & 0x1FFF) == offset;
}

bool cord_match_ipv4_ttl(const cord_ipv4_hdr_t *ip, uint8_t ttl)
{
    return ip->ttl == ttl;
}

bool cord_match_ipv4_protocol(const cord_ipv4_hdr_t *ip, uint8_t protocol)
{
    return ip->protocol == protocol;
}

bool cord_match_ipv4_checksum(const cord_ipv4_hdr_t *ip, uint16_t checksum)
{
    return ip->check == checksum;
}

bool cord_match_ipv4_src_addr(const cord_ipv4_hdr_t *ip, uint32_t addr)
{
    return ip->saddr.addr == addr;
}

bool cord_match_ipv4_dst_addr(const cord_ipv4_hdr_t *ip, uint32_t addr)
{
    return ip->daddr.addr == addr;
}

bool cord_match_ipv4_src_subnet(const cord_ipv4_hdr_t *ip, uint32_t subnet, uint32_t mask)
{
    return (ip->saddr.addr & mask) == (subnet & mask);
}

bool cord_match_ipv4_dst_subnet(const cord_ipv4_hdr_t *ip, uint32_t subnet, uint32_t mask)
{
    return (ip->daddr.addr & mask) == (subnet & mask);
}

bool cord_match_ipv4_fragmented(const cord_ipv4_hdr_t *ip)
{
    uint16_t frag_info = cord_ntohs(ip->frag_off);
    return (frag_info & 0x1FFF) != 0 || (frag_info & 0x2000) != 0; // Has offset or MF flag
}

bool cord_match_ipv4_first_fragment(const cord_ipv4_hdr_t *ip)
{
    uint16_t frag_info = cord_ntohs(ip->frag_off);
    return (frag_info & 0x1FFF) == 0 && (frag_info & 0x2000) != 0; // No offset but MF flag set
}

bool cord_match_ipv4_last_fragment(const cord_ipv4_hdr_t *ip)
{
    uint16_t frag_info = cord_ntohs(ip->frag_off);
    return (frag_info & 0x1FFF) != 0 && (frag_info & 0x2000) == 0; // Has offset but no MF flag
}

// IPv6 Match Functions
bool cord_match_ipv6_version(const cord_ipv6_hdr_t *ip6)
{
    return cord_get_ipv6_version(ip6) == 6;
}

bool cord_match_ipv6_traffic_class(const cord_ipv6_hdr_t *ip6, uint8_t tc)
{
    return cord_get_ipv6_traffic_class(ip6) == tc;
}

bool cord_match_ipv6_flow_label(const cord_ipv6_hdr_t *ip6, uint32_t flow)
{
    return cord_get_ipv6_flow_label(ip6) == flow;
}

bool cord_match_ipv6_payload_length(const cord_ipv6_hdr_t *ip6, uint16_t length)
{
    return cord_ntohs(ip6->payload_len) == length;
}

bool cord_match_ipv6_next_header(const cord_ipv6_hdr_t *ip6, uint8_t next_hdr)
{
    return ip6->nexthdr == next_hdr;
}

bool cord_match_ipv6_hop_limit(const cord_ipv6_hdr_t *ip6, uint8_t hop_limit)
{
    return ip6->hop_limit == hop_limit;
}

bool cord_match_ipv6_src_addr(const cord_ipv6_hdr_t *ip6, const cord_ipv6_addr_t *addr)
{
    for (int i = 0; i < 4; i++) {
        if (((uint32_t*)ip6->saddr.addr)[i] != ((uint32_t*)addr->addr)[i]) {
            return false;
        }
    }
    return true;
}

bool cord_match_ipv6_dst_addr(const cord_ipv6_hdr_t *ip6, const cord_ipv6_addr_t *addr)
{
    for (int i = 0; i < 4; i++) {
        if (((uint32_t*)ip6->daddr.addr)[i] != ((uint32_t*)addr->addr)[i]) {
            return false;
        }
    }
    return true;
}

bool cord_match_ipv6_src_prefix(const cord_ipv6_hdr_t *ip6, const cord_ipv6_addr_t *prefix, uint8_t prefix_len)
{
    if (prefix_len > 128) {
        return false;
    }
    
    // Calculate how many full 32-bit words to compare
    uint8_t full_words = prefix_len / 32;
    uint8_t remaining_bits = prefix_len % 32;
    
    // Compare full words
    for (uint8_t i = 0; i < full_words; i++) {
        if (((uint32_t*)ip6->saddr.addr)[i] != ((uint32_t*)prefix->addr)[i]) {
            return false;
        }
    }
    
    // Compare remaining bits if any
    if (remaining_bits > 0 && full_words < 4) {
        uint32_t mask = cord_htonl(0xFFFFFFFF << (32 - remaining_bits));
        if ((((uint32_t*)ip6->saddr.addr)[full_words] & mask) != (((uint32_t*)prefix->addr)[full_words] & mask)) {
            return false;
        }
    }
    
    return true;
}

bool cord_match_ipv6_dst_prefix(const cord_ipv6_hdr_t *ip6, const cord_ipv6_addr_t *prefix, uint8_t prefix_len)
{
    if (prefix_len > 128) {
        return false;
    }
    
    // Calculate how many full 32-bit words to compare
    uint8_t full_words = prefix_len / 32;
    uint8_t remaining_bits = prefix_len % 32;
    
    // Compare full words
    for (uint8_t i = 0; i < full_words; i++) {
        if (((uint32_t*)ip6->daddr.addr)[i] != ((uint32_t*)prefix->addr)[i]) {
            return false;
        }
    }
    
    // Compare remaining bits if any
    if (remaining_bits > 0 && full_words < 4) {
        uint32_t mask = cord_htonl(0xFFFFFFFF << (32 - remaining_bits));
        if ((((uint32_t*)ip6->daddr.addr)[full_words] & mask) != (((uint32_t*)prefix->addr)[full_words] & mask)) {
            return false;
        }
    }
    
    return true;
}

// ICMP Match Functions
bool cord_match_icmp_type(const cord_icmp_hdr_t *icmp, uint8_t type)
{
    return icmp->type == type;
}

bool cord_match_icmp_code(const cord_icmp_hdr_t *icmp, uint8_t code)
{
    return icmp->code == code;
}

bool cord_match_icmp_echo_request(const cord_icmp_hdr_t *icmp)
{
    return icmp->type == CORD_ICMP_ECHO;
}

bool cord_match_icmp_echo_reply(const cord_icmp_hdr_t *icmp)
{
    return icmp->type == CORD_ICMP_ECHOREPLY;
}

bool cord_match_icmp_dest_unreachable(const cord_icmp_hdr_t *icmp)
{
    return icmp->type == CORD_ICMP_DEST_UNREACH;
}

// =============================================================================
// OSI LAYER 4 (TRANSPORT) - PROTOCOL FIELD MATCHING FUNCTIONS
// =============================================================================

// TCP Match Functions
bool cord_match_tcp_src_port(const cord_tcp_hdr_t *tcp, uint16_t port)
{
    return cord_ntohs(tcp->source) == port;
}

bool cord_match_tcp_dst_port(const cord_tcp_hdr_t *tcp, uint16_t port)
{
    return cord_ntohs(tcp->dest) == port;
}

bool cord_match_tcp_port_range(const cord_tcp_hdr_t *tcp, uint16_t min_port, uint16_t max_port, bool check_src)
{
    uint16_t port = check_src ? cord_ntohs(tcp->source) : cord_ntohs(tcp->dest);
    return port >= min_port && port <= max_port;
}

bool cord_match_tcp_seq_num(const cord_tcp_hdr_t *tcp, uint32_t seq)
{
    return cord_ntohl(tcp->seq) == seq;
}

bool cord_match_tcp_ack_num(const cord_tcp_hdr_t *tcp, uint32_t ack)
{
    return cord_ntohl(tcp->ack_seq) == ack;
}

bool cord_match_tcp_data_offset(const cord_tcp_hdr_t *tcp, uint8_t offset)
{
    return (tcp->doff) == offset;
}

bool cord_match_tcp_window(const cord_tcp_hdr_t *tcp, uint16_t window)
{
    return cord_ntohs(tcp->window) == window;
}

bool cord_match_tcp_checksum(const cord_tcp_hdr_t *tcp, uint16_t checksum)
{
    return tcp->check == checksum;
}

bool cord_match_tcp_urgent_ptr(const cord_tcp_hdr_t *tcp, uint16_t urg_ptr)
{
    return cord_ntohs(tcp->urg_ptr) == urg_ptr;
}

bool cord_match_tcp_syn(const cord_tcp_hdr_t *tcp)
{
    return tcp->syn;
}

bool cord_match_tcp_ack(const cord_tcp_hdr_t *tcp)
{
    return tcp->ack;
}

bool cord_match_tcp_fin(const cord_tcp_hdr_t *tcp)
{
    return tcp->fin;
}

bool cord_match_tcp_rst(const cord_tcp_hdr_t *tcp)
{
    return tcp->rst;
}

bool cord_match_tcp_psh(const cord_tcp_hdr_t *tcp)
{
    return tcp->psh;
}

bool cord_match_tcp_urg(const cord_tcp_hdr_t *tcp)
{
    return tcp->urg;
}

bool cord_match_tcp_ece(const cord_tcp_hdr_t *tcp)
{
    return tcp->ece;
}

bool cord_match_tcp_cwr(const cord_tcp_hdr_t *tcp)
{
    return tcp->cwr;
}

bool cord_match_tcp_established(const cord_tcp_hdr_t *tcp)
{
    return tcp->ack && 
           tcp->syn == 0;
}

bool cord_match_tcp_connection_request(const cord_tcp_hdr_t *tcp)
{
    return tcp->syn && 
           tcp->ack == 0;
}

// UDP Match Functions
bool cord_match_udp_src_port(const cord_udp_hdr_t *udp, uint16_t port)
{
    return cord_ntohs(udp->source) == port;
}

bool cord_match_udp_dst_port(const cord_udp_hdr_t *udp, uint16_t port)
{
    return cord_ntohs(udp->dest) == port;
}

bool cord_match_udp_port_range(const cord_udp_hdr_t *udp, uint16_t min_port, uint16_t max_port, bool check_src)
{
    uint16_t port = check_src ? cord_ntohs(udp->source) : cord_ntohs(udp->dest);
    return port >= min_port && port <= max_port;
}

bool cord_match_udp_length(const cord_udp_hdr_t *udp, uint16_t length)
{
    return cord_ntohs(udp->len) == length;
}

bool cord_match_udp_checksum(const cord_udp_hdr_t *udp, uint16_t checksum)
{
    return udp->check == checksum;
}

// SCTP Match Functions
bool cord_match_sctp_src_port(const cord_sctp_hdr_t *sctp, uint16_t port)
{
    return cord_ntohs(sctp->source) == port;
}

bool cord_match_sctp_dst_port(const cord_sctp_hdr_t *sctp, uint16_t port)
{
    return cord_ntohs(sctp->dest) == port;
}

bool cord_match_sctp_port_range(const cord_sctp_hdr_t *sctp, uint16_t min_port, uint16_t max_port, bool check_src)
{
    uint16_t port = check_src ? cord_ntohs(sctp->source) : cord_ntohs(sctp->dest);
    return port >= min_port && port <= max_port;
}

bool cord_match_sctp_vtag(const cord_sctp_hdr_t *sctp, uint32_t vtag)
{
    return cord_ntohl(sctp->vtag) == vtag;
}

bool cord_match_sctp_checksum(const cord_sctp_hdr_t *sctp, uint32_t checksum)
{
    return sctp->checksum == checksum;
}

// =============================================================================
// TUNNELING PROTOCOLS - PROTOCOL FIELD MATCHING FUNCTIONS
// =============================================================================

// GRE Protocol Match Functions
bool cord_match_gre_checksum_present(const cord_gre_hdr_t *gre)
{
    return (cord_ntohs(gre->flags_version) & CORD_GRE_CSUM) != 0;
}

bool cord_match_gre_key_present(const cord_gre_hdr_t *gre)
{
    return (cord_ntohs(gre->flags_version) & CORD_GRE_KEY) != 0;
}

bool cord_match_gre_sequence_present(const cord_gre_hdr_t *gre)
{
    return (cord_ntohs(gre->flags_version) & CORD_GRE_SEQ) != 0;
}

bool cord_match_gre_protocol(const cord_gre_hdr_t *gre, uint16_t protocol)
{
    return cord_ntohs(gre->protocol) == protocol;
}

// VXLAN Protocol Match Functions
bool cord_match_vxlan_vni(const cord_vxlan_hdr_t *vxlan, uint32_t vni)
{
    return ((vxlan->vni[0] << 16) | (vxlan->vni[1] << 8) | vxlan->vni[2]) == vni;
}

bool cord_match_vxlan_flags(const cord_vxlan_hdr_t *vxlan, uint8_t flags)
{
    return vxlan->flags == flags;
}

// GTP-U Protocol Match Functions
bool cord_match_gtpu_teid(const cord_gtpu_hdr_t *gtpu, uint32_t teid)
{
    return cord_ntohl(gtpu->teid) == teid;
}

bool cord_match_gtpu_msg_type(const cord_gtpu_hdr_t *gtpu, uint8_t msg_type)
{
    return gtpu->message_type == msg_type;
}

// =============================================================================
// APPLICATION LAYER - ADVANCED PROTOCOL ANALYSIS FUNCTIONS
// =============================================================================

// DNS Protocol Analysis
bool cord_match_is_dns_query(const cord_udp_hdr_t *udp)
{
    return cord_ntohs(udp->dest) == CORD_PORT_DNS;
}

bool cord_match_is_dns_response(const cord_udp_hdr_t *udp)
{
    return cord_ntohs(udp->source) == CORD_PORT_DNS;
}

// DHCP Protocol Analysis
bool cord_match_is_dhcp_request(const cord_udp_hdr_t *udp)
{
    return cord_ntohs(udp->dest) == CORD_PORT_DHCP_SERVER;
}

bool cord_match_is_dhcp_response(const cord_udp_hdr_t *udp)
{
    return cord_ntohs(udp->source) == CORD_PORT_DHCP_SERVER;
}

// HTTP/HTTPS Protocol Analysis
bool cord_match_is_http_request(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohs(tcp->dest) == CORD_PORT_HTTP;
}

bool cord_match_is_http_response(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohs(tcp->source) == CORD_PORT_HTTP;
}

bool cord_match_is_https_traffic(const cord_tcp_hdr_t *tcp)
{
    uint16_t src_port = cord_ntohs(tcp->source);
    uint16_t dst_port = cord_ntohs(tcp->dest);
    return src_port == CORD_PORT_HTTPS || dst_port == CORD_PORT_HTTPS;
}

// SSH Protocol Analysis
bool cord_match_is_ssh_traffic(const cord_tcp_hdr_t *tcp)
{
    uint16_t src_port = cord_ntohs(tcp->source);
    uint16_t dst_port = cord_ntohs(tcp->dest);
    return src_port == CORD_PORT_SSH || dst_port == CORD_PORT_SSH;
}

// =============================================================================
// CROSS-LAYER PERFORMANCE UTILITIES
// =============================================================================

// Single function to extract all common protocol information
bool cord_match_extract_protocol_info(const void *buffer, size_t len, cord_protocol_info_t *info)
{
    if (!buffer || !info || len < sizeof(cord_eth_hdr_t)) {
        return false;
    }
    
    // Initialize the structure
    memset(info, 0, sizeof(cord_protocol_info_t));
    
    // Start with Ethernet header
    const cord_eth_hdr_t *eth = (const cord_eth_hdr_t*)buffer;
    info->eth_type = cord_ntohs(eth->h_proto);
    
    size_t offset = sizeof(cord_eth_hdr_t);
    
    // Check for VLAN tags
    if (info->eth_type == CORD_ETH_P_8021Q || info->eth_type == CORD_ETH_P_8021AD) {
        if (len < offset + sizeof(cord_vlan_hdr_t)) return false;
        
        const cord_vlan_hdr_t *vlan = (const cord_vlan_hdr_t*)((uint8_t*)buffer + offset);
        info->has_vlan = true;
        info->vlan_vid = cord_ntohs(vlan->tci) & 0x0FFF;
        info->eth_type = cord_ntohs(vlan->h_proto);
        offset += sizeof(cord_vlan_hdr_t);
    }
    
    // Parse IP header
    if (info->eth_type == CORD_ETH_P_IP) {
        if (len < offset + sizeof(cord_ipv4_hdr_t)) return false;
        
        const cord_ipv4_hdr_t *ip = (const cord_ipv4_hdr_t*)((uint8_t*)buffer + offset);
        info->ip_version = 4;
        info->ip_protocol = ip->protocol;
        info->l3_src_addr = cord_ntohl(ip->saddr.addr);
        info->l3_dst_addr = cord_ntohl(ip->daddr.addr);
        info->is_fragment = (cord_ntohs(ip->frag_off) & 0x1FFF) != 0 || (cord_ntohs(ip->frag_off) & 0x2000) != 0;
        
        uint8_t ihl = (ip->ihl) * 4;
        offset += ihl;
        
        // Parse Layer 4 headers
        if (!info->is_fragment && ip->protocol == CORD_IPPROTO_TCP) {
            if (len >= offset + sizeof(cord_tcp_hdr_t)) {
                const cord_tcp_hdr_t *tcp = (const cord_tcp_hdr_t*)((uint8_t*)buffer + offset);
                info->l4_src_port = cord_ntohs(tcp->source);
                info->l4_dst_port = cord_ntohs(tcp->dest);
            }
        } else if (!info->is_fragment && ip->protocol == CORD_IPPROTO_UDP) {
            if (len >= offset + sizeof(cord_udp_hdr_t)) {
                const cord_udp_hdr_t *udp = (const cord_udp_hdr_t*)((uint8_t*)buffer + offset);
                info->l4_src_port = cord_ntohs(udp->source);
                info->l4_dst_port = cord_ntohs(udp->dest);
            }
        }
        
        info->payload_len = cord_ntohs(ip->tot_len) - ihl;
        
    } else if (info->eth_type == CORD_ETH_P_IPV6) {
        if (len < offset + sizeof(cord_ipv6_hdr_t)) return false;
        
        const cord_ipv6_hdr_t *ip6 = (const cord_ipv6_hdr_t*)((uint8_t*)buffer + offset);
        info->ip_version = 6;
        info->ip_protocol = ip6->nexthdr;
        // For IPv6, we only store the first 32 bits of src/dst in the 32-bit fields
        info->l3_src_addr = cord_ntohl(((uint32_t*)ip6->saddr.addr)[0]);
        info->l3_dst_addr = cord_ntohl(((uint32_t*)ip6->daddr.addr)[0]);
        info->is_fragment = false; // Simplified - would need to parse extension headers
        
        offset += sizeof(cord_ipv6_hdr_t);
        
        // Parse Layer 4 headers (simplified - doesn't handle extension headers)
        if (ip6->nexthdr == CORD_IPPROTO_TCP) {
            if (len >= offset + sizeof(cord_tcp_hdr_t)) {
                const cord_tcp_hdr_t *tcp = (const cord_tcp_hdr_t*)((uint8_t*)buffer + offset);
                info->l4_src_port = cord_ntohs(tcp->source);
                info->l4_dst_port = cord_ntohs(tcp->dest);
            }
        } else if (ip6->nexthdr == CORD_IPPROTO_UDP) {
            if (len >= offset + sizeof(cord_udp_hdr_t)) {
                const cord_udp_hdr_t *udp = (const cord_udp_hdr_t*)((uint8_t*)buffer + offset);
                info->l4_src_port = cord_ntohs(udp->source);
                info->l4_dst_port = cord_ntohs(udp->dest);
            }
        }
        
        info->payload_len = cord_ntohs(ip6->payload_len);
    }
    
    return true;
}

// Fast 5-tuple extraction for flow identification
bool cord_match_extract_flow_tuple(const void *buffer, size_t len, cord_flow_tuple_t *tuple)
{
    if (!buffer || !tuple || len < sizeof(cord_eth_hdr_t)) {
        return false;
    }
    
    // Initialize the structure
    memset(tuple, 0, sizeof(cord_flow_tuple_t));
    
    // Start with Ethernet header
    const cord_eth_hdr_t *eth = (const cord_eth_hdr_t*)buffer;
    uint16_t eth_type = cord_ntohs(eth->h_proto);
    
    size_t offset = sizeof(cord_eth_hdr_t);
    
    // Skip VLAN tags
    while ((eth_type == CORD_ETH_P_8021Q || eth_type == CORD_ETH_P_8021AD) && 
           len >= offset + sizeof(cord_vlan_hdr_t)) {
        const cord_vlan_hdr_t *vlan = (const cord_vlan_hdr_t*)((uint8_t*)buffer + offset);
        eth_type = cord_ntohs(vlan->h_proto);
        offset += sizeof(cord_vlan_hdr_t);
    }
    
    // Parse IPv4
    if (eth_type == CORD_ETH_P_IP && len >= offset + sizeof(cord_ipv4_hdr_t)) {
        const cord_ipv4_hdr_t *ip = (const cord_ipv4_hdr_t*)((uint8_t*)buffer + offset);
        
        tuple->src_addr = cord_ntohl(ip->saddr.addr);
        tuple->dst_addr = cord_ntohl(ip->daddr.addr);
        tuple->protocol = ip->protocol;
        
        // Check for fragments
        if ((cord_ntohs(ip->frag_off) & 0x1FFF) != 0) {
            return true; // Fragment - no port info available
        }
        
        uint8_t ihl = (ip->ihl) * 4;
        offset += ihl;
        
        // Extract port information
        if (tuple->protocol == CORD_IPPROTO_TCP && len >= offset + sizeof(cord_tcp_hdr_t)) {
            const cord_tcp_hdr_t *tcp = (const cord_tcp_hdr_t*)((uint8_t*)buffer + offset);
            tuple->src_port = cord_ntohs(tcp->source);
            tuple->dst_port = cord_ntohs(tcp->dest);
        } else if (tuple->protocol == CORD_IPPROTO_UDP && len >= offset + sizeof(cord_udp_hdr_t)) {
            const cord_udp_hdr_t *udp = (const cord_udp_hdr_t*)((uint8_t*)buffer + offset);
            tuple->src_port = cord_ntohs(udp->source);
            tuple->dst_port = cord_ntohs(udp->dest);
        } else if (tuple->protocol == CORD_IPPROTO_SCTP && len >= offset + sizeof(cord_sctp_hdr_t)) {
            const cord_sctp_hdr_t *sctp = (const cord_sctp_hdr_t*)((uint8_t*)buffer + offset);
            tuple->src_port = cord_ntohs(sctp->source);
            tuple->dst_port = cord_ntohs(sctp->dest);
        }
        
        return true;
    }
    
    return false;
}

// High-performance hash calculation for flow tables
uint32_t cord_match_hash_flow_tuple(const cord_flow_tuple_t *tuple)
{
    if (!tuple) {
        return 0;
    }
    
    // Simple but effective hash function for 5-tuple
    // Uses a combination of XOR and bit rotation for good distribution
    uint32_t hash = tuple->src_addr;
    hash ^= tuple->dst_addr;
    hash ^= (tuple->src_port << 16) | tuple->dst_port;
    hash ^= tuple->protocol;
    
    // Additional mixing
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;
    
    return hash;
}

// =============================================================================
// CROSS-LAYER ADDRESS UTILITIES
// =============================================================================

// IPv4 address utilities (implemented as part of cross-layer utilities)
bool cord_ipv4_is_multicast(uint32_t addr)
{
    // Multicast range: 224.0.0.0 to 239.255.255.255 (224.0.0.0/4)
    uint32_t addr_host = cord_ntohl(addr);
    return (addr_host >= 0xE0000000) && (addr_host <= 0xEFFFFFFF);
}

bool cord_ipv4_is_broadcast(uint32_t addr)
{
    return addr == 0xFFFFFFFF; // 255.255.255.255 in network byte order
}

// Layer 2 Address Type Detection
bool cord_mac_is_multicast(const cord_mac_addr_t *mac_addr)
{
    return (mac_addr->addr[0] & 0x01) != 0;
}

bool cord_mac_is_broadcast(const cord_mac_addr_t *mac_addr)
{
    static const uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return memcmp(mac_addr, broadcast, 6) == 0;
}

// =============================================================================
// ADDITIONAL UTILITY FUNCTIONS (CROSS-LAYER SUPPORT)
// =============================================================================

// IPv4 checksum calculation
uint16_t cord_ipv4_checksum(const cord_ipv4_hdr_t *ip_hdr)
{
    uint32_t sum = 0;
    const uint8_t *ptr = (const uint8_t*)ip_hdr;
    uint8_t ihl = ip_hdr->ihl * 4; // Header length in bytes
    
    // Save original checksum and zero it for calculation
    uint16_t orig_check = ip_hdr->check;
    
    // Sum all 16-bit words in the header (skip checksum field)
    for (uint8_t i = 0; i < ihl; i += 2) {
        if (i == 10) continue; // Skip checksum field at offset 10-11
        uint16_t word = (ptr[i] << 8) | ptr[i + 1];
        sum += word;
    }
    
    // Restore original checksum
    *((uint16_t*)&ip_hdr->check) = orig_check;
    
    // Add carry bits and take one's complement
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

// IPv4 checksum validation
bool cord_ipv4_checksum_valid(const cord_ipv4_hdr_t *ip_hdr)
{
    uint32_t sum = 0;
    const uint8_t *ptr = (const uint8_t*)ip_hdr;
    uint8_t ihl = ip_hdr->ihl * 4; // Header length in bytes
    
    // Sum all 16-bit words including checksum field
    for (uint8_t i = 0; i < ihl; i += 2) {
        uint16_t word = (ptr[i] << 8) | ptr[i + 1];
        sum += word;
    }
    
    // Add carry bits and take one's complement
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // For a valid checksum, the result should be 0
    return (~sum) == 0;
}

// IPv4 payload length calculation
uint16_t cord_ipv4_payload_length(const cord_ipv4_hdr_t *ip_hdr)
{
    uint16_t total_len = cord_ntohs(ip_hdr->tot_len);
    uint8_t hdr_len = ip_hdr->ihl * 4;
    return total_len - hdr_len;
}

// IPv6 payload length getter
uint16_t cord_ipv6_payload_length(const cord_ipv6_hdr_t *ip6_hdr)
{
    return cord_ntohs(ip6_hdr->payload_len);
}

// TCP checksum calculation for IPv4
uint16_t cord_tcp_checksum_ipv4(const cord_ipv4_hdr_t *ip_hdr)
{
    // Verify this is a TCP packet
    if (ip_hdr->protocol != CORD_IPPROTO_TCP) {
        return 0; // Invalid protocol
    }
    
    // Calculate IP header length and find TCP header
    uint8_t ip_hdr_len = ip_hdr->ihl * 4;
    const cord_tcp_hdr_t *tcp_hdr = (const cord_tcp_hdr_t*)((const uint8_t*)ip_hdr + ip_hdr_len);
    
    uint32_t sum = 0;
    uint16_t tcp_len = cord_ipv4_payload_length(ip_hdr);
    
    // Pseudo header: src addr + dst addr + zero + protocol + length
    // Source address (network byte order, split into 16-bit words)
    sum += cord_ntohs((ip_hdr->saddr.addr >> 16) & 0xFFFF);
    sum += cord_ntohs(ip_hdr->saddr.addr & 0xFFFF);
    // Destination address (network byte order, split into 16-bit words)
    sum += cord_ntohs((ip_hdr->daddr.addr >> 16) & 0xFFFF);
    sum += cord_ntohs(ip_hdr->daddr.addr & 0xFFFF);
    // Zero byte + protocol (6 for TCP) - in network byte order
    sum += CORD_IPPROTO_TCP;
    // TCP length
    sum += tcp_len;
    
    // TCP header and data
    const uint8_t *ptr = (const uint8_t*)tcp_hdr;
    
    // Sum all 16-bit words, skipping checksum field at offset 16-17
    for (uint16_t i = 0; i < tcp_len / 2; i++) {
        if (i == 8) continue; // Skip checksum field (offset 16-17 = word 8)
        uint16_t word = (ptr[i*2] << 8) | ptr[i*2 + 1];
        sum += word;
    }
    
    // Handle odd byte
    if (tcp_len & 1) {
        sum += ptr[tcp_len - 1] << 8;
    }
    
    // Add carry bits and take one's complement
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

// UDP checksum calculation for IPv4
uint16_t cord_udp_checksum_ipv4(const cord_ipv4_hdr_t *ip_hdr)
{
    // Verify this is a UDP packet
    if (ip_hdr->protocol != CORD_IPPROTO_UDP) {
        return 0; // Invalid protocol
    }
    
    // Calculate IP header length and find UDP header
    uint8_t ip_hdr_len = ip_hdr->ihl * 4;
    const cord_udp_hdr_t *udp_hdr = (const cord_udp_hdr_t*)((const uint8_t*)ip_hdr + ip_hdr_len);
    
    uint32_t sum = 0;
    uint16_t udp_len = cord_ntohs(udp_hdr->len);
    
    // Pseudo header: src addr + dst addr + zero + protocol + length
    // Source address (network byte order, split into 16-bit words)
    sum += cord_ntohs((ip_hdr->saddr.addr >> 16) & 0xFFFF);
    sum += cord_ntohs(ip_hdr->saddr.addr & 0xFFFF);
    // Destination address (network byte order, split into 16-bit words)
    sum += cord_ntohs((ip_hdr->daddr.addr >> 16) & 0xFFFF);
    sum += cord_ntohs(ip_hdr->daddr.addr & 0xFFFF);
    // Zero byte + protocol (17 for UDP) - in network byte order
    sum += CORD_IPPROTO_UDP;
    // UDP length - already converted to host byte order above
    sum += udp_len;
    
    // UDP header and data
    const uint8_t *ptr = (const uint8_t*)udp_hdr;
    
    // Sum all 16-bit words, skipping checksum field at offset 6-7
    for (uint16_t i = 0; i < udp_len / 2; i++) {
        if (i == 3) continue; // Skip checksum field (offset 6-7 = word 3)
        uint16_t word = (ptr[i*2] << 8) | ptr[i*2 + 1];
        sum += word;
    }
    
    // Handle odd byte
    if (udp_len & 1) {
        sum += ptr[udp_len - 1] << 8;
    }
    
    // Add carry bits and take one's complement
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

// ICMP checksum calculation for IPv4
uint16_t cord_icmp_checksum_ipv4(const cord_ipv4_hdr_t *ip_hdr)
{
    // Verify this is an ICMP packet
    if (ip_hdr->protocol != CORD_IPPROTO_ICMP) {
        return 0; // Invalid protocol
    }
    
    // Calculate IP header length and find ICMP header
    uint8_t ip_hdr_len = ip_hdr->ihl * 4;
    const cord_icmp_hdr_t *icmp_hdr = (const cord_icmp_hdr_t*)((const uint8_t*)ip_hdr + ip_hdr_len);
    
    // Calculate ICMP data length
    uint16_t total_len = cord_ntohs(ip_hdr->tot_len);
    uint16_t icmp_len = total_len - ip_hdr_len;
    
    uint32_t sum = 0;
    const uint8_t *ptr = (const uint8_t*)icmp_hdr;
    
    // Sum all 16-bit words, skipping checksum field at offset 2-3
    for (uint16_t i = 0; i < icmp_len / 2; i++) {
        if (i == 1) continue; // Skip checksum field (offset 2-3 = word 1)
        uint16_t word = (ptr[i*2] << 8) | ptr[i*2 + 1];
        sum += word;
    }
    
    // Handle odd byte
    if (icmp_len & 1) {
        sum += ptr[icmp_len - 1] << 8;
    }
    
    // Add carry bits and take one's complement
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

// IPv6 extension header parser
void* cord_ipv6_parse_ext_headers(const cord_ipv6_hdr_t *ip6_hdr, 
                                  uint8_t *final_protocol, 
                                  uint16_t *header_len)
{
    if (!ip6_hdr || !final_protocol || !header_len) {
        return NULL;
    }
    
    uint8_t next_hdr = ip6_hdr->nexthdr;
    uint8_t *current = (uint8_t*)ip6_hdr + sizeof(cord_ipv6_hdr_t);
    uint16_t offset = sizeof(cord_ipv6_hdr_t);
    
    // Parse extension headers
    while (next_hdr == CORD_IPPROTO_HOPOPTS || 
           next_hdr == CORD_IPPROTO_ROUTING ||
           next_hdr == CORD_IPPROTO_FRAGMENT ||
           next_hdr == CORD_IPPROTO_DSTOPTS) {
        
        if (next_hdr == CORD_IPPROTO_FRAGMENT) {
            // Fragment header is fixed 8 bytes
            if (offset + 8 > 1500) break; // Sanity check
            next_hdr = current[0];
            current += 8;
            offset += 8;
        } else {
            // Other extension headers have length field
            if (offset + 2 > 1500) break; // Sanity check
            uint8_t ext_len = current[1];
            uint16_t total_len = (ext_len + 1) * 8;
            
            next_hdr = current[0];
            current += total_len;
            offset += total_len;
            
            if (offset > 1500) break; // Sanity check
        }
    }
    
    *final_protocol = next_hdr;
    *header_len = offset;
    
    return current;
}

// String conversion utilities
char* cord_ipv4_to_string(uint32_t addr, char *buf)
{
    if (!buf) return NULL;
    
    uint32_t addr_host = cord_ntohl(addr);
    snprintf(buf, 16, "%u.%u.%u.%u",
             (addr_host >> 24) & 0xFF,
             (addr_host >> 16) & 0xFF,
             (addr_host >> 8) & 0xFF,
             addr_host & 0xFF);
    
    return buf;
}

char* cord_mac_to_string(const cord_mac_addr_t *mac_addr, char *buf)
{
    if (!mac_addr || !buf) return NULL;
    
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_addr->addr[0], mac_addr->addr[1], mac_addr->addr[2],
             mac_addr->addr[3], mac_addr->addr[4], mac_addr->addr[5]);
    
    return buf;
}

// Packet validation utilities
bool cord_packet_basic_validation(const void *buffer, size_t buf_len)
{
    if (!buffer || buf_len < sizeof(cord_eth_hdr_t)) {
        return false;
    }
    
    const cord_eth_hdr_t *eth = (const cord_eth_hdr_t*)buffer;
    uint16_t eth_type = cord_ntohs(eth->h_proto);
    size_t offset = sizeof(cord_eth_hdr_t);
    
    // Skip VLAN tags
    while ((eth_type == CORD_ETH_P_8021Q || eth_type == CORD_ETH_P_8021AD) && 
           buf_len >= offset + sizeof(cord_vlan_hdr_t)) {
        const cord_vlan_hdr_t *vlan = (const cord_vlan_hdr_t*)((uint8_t*)buffer + offset);
        eth_type = cord_ntohs(vlan->h_proto);
        offset += sizeof(cord_vlan_hdr_t);
    }
    
    // Validate IP headers
    if (eth_type == CORD_ETH_P_IP) {
        if (buf_len < offset + sizeof(cord_ipv4_hdr_t)) {
            return false;
        }
        
        const cord_ipv4_hdr_t *ip = (const cord_ipv4_hdr_t*)((uint8_t*)buffer + offset);
        
        // Check version
        if ((ip->version) != 4) {
            return false;
        }
        
        // Check IHL
        uint8_t ihl = (ip->ihl);
        if (ihl < 5 || ihl > 15) {
            return false;
        }
        
        // Check total length
        uint16_t total_len = cord_ntohs(ip->tot_len);
        if (total_len < ihl * 4 || offset + total_len > buf_len) {
            return false;
        }
        
        return true;
        
    } else if (eth_type == CORD_ETH_P_IPV6) {
        if (buf_len < offset + sizeof(cord_ipv6_hdr_t)) {
            return false;
        }
        
        const cord_ipv6_hdr_t *ip6 = (const cord_ipv6_hdr_t*)((uint8_t*)buffer + offset);
        
        // Check version
        if ((ip6->version) != 6) {
            return false;
        }
        
        // Check payload length
        uint16_t payload_len = cord_ntohs(ip6->payload_len);
        if (offset + sizeof(cord_ipv6_hdr_t) + payload_len > buf_len) {
            return false;
        }
        
        return true;
    }
    
    return true; // Non-IP packets are considered valid at this level
}

// VLAN tag extraction utility
uint8_t cord_extract_vlan_tags(const void *buffer, uint16_t *vlan_tags, uint8_t max_tags)
{
    if (!buffer || !vlan_tags || max_tags == 0) {
        return 0;
    }
    
    const cord_eth_hdr_t *eth = (const cord_eth_hdr_t*)buffer;
    uint16_t eth_type = cord_ntohs(eth->h_proto);
    size_t offset = sizeof(cord_eth_hdr_t);
    uint8_t tag_count = 0;
    
    // Extract VLAN tags
    while ((eth_type == CORD_ETH_P_8021Q || eth_type == CORD_ETH_P_8021AD) && 
           tag_count < max_tags) {
        const cord_vlan_hdr_t *vlan = (const cord_vlan_hdr_t*)((uint8_t*)buffer + offset);
        vlan_tags[tag_count] = cord_ntohs(vlan->tci) & 0x0FFF;
        tag_count++;
        
        eth_type = cord_ntohs(vlan->h_proto);
        offset += sizeof(cord_vlan_hdr_t);
    }
    
    return tag_count;
}

// Ethernet frame CRC32 calculation
uint32_t cord_ethernet_crc32(const void *buffer, size_t frame_len)
{
    // Standard Ethernet CRC32 polynomial: 0x04C11DB7
    static const uint32_t crc_table[256] = {
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
        0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
        0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
        0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
        0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
        0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
        0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
        0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
        0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
        0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
        0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
        0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
        0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
        0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
        0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
        0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
        0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
        0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
        0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
        0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
        0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
        0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
        0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
        0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
        0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
        0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
        0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
        0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
        0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
        0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
        0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
        0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
        0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
        0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
        0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
        0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
        0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
        0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
        0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
        0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
    };
    
    uint32_t crc = 0xFFFFFFFF;
    const uint8_t *data = (const uint8_t*)buffer;
    
    for (size_t i = 0; i < frame_len; i++) {
        crc = crc_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    
    return ~crc;
}