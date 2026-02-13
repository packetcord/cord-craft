#include <protocols/cord_protocols.h>

//
// From MATCH
//
// Layer 2 Protocol Headers
cord_eth_hdr_t* cord_header_eth(const void *buffer)
{
    return (cord_eth_hdr_t *)buffer;
}

cord_vlan_hdr_t* cord_header_vlan(const cord_eth_hdr_t *eth_hdr)
{
    uint16_t eth_type = cord_ntohs(eth_hdr->h_proto);
    if (eth_type == CORD_ETH_P_8021Q || eth_type == CORD_ETH_P_8021AD) {
        return (cord_vlan_hdr_t *)((uint8_t *)eth_hdr + sizeof(cord_eth_hdr_t));
    }
    return NULL;
}

cord_mpls_hdr_t* cord_header_mpls(const void *buffer, uint16_t offset)
{
    return (cord_mpls_hdr_t *)((uint8_t *)buffer + offset);
}

cord_arp_hdr_t* cord_header_arp(const cord_eth_hdr_t *eth_hdr)
{
    if (cord_ntohs(eth_hdr->h_proto) != CORD_ETH_P_ARP) {
        return NULL;
    }
    return (cord_arp_hdr_t *)((uint8_t *)eth_hdr + sizeof(cord_eth_hdr_t));
}

// Layer 3 Protocol Headers
cord_ipv4_hdr_t* cord_header_ipv4(const void *buffer)
{
    return (cord_ipv4_hdr_t *)buffer;
}

cord_ipv4_hdr_t* cord_header_ipv4_from_eth(const cord_eth_hdr_t *eth_hdr)
{
    if (cord_ntohs(eth_hdr->h_proto) != CORD_ETH_P_IP) {
        return NULL;
    }
    return (cord_ipv4_hdr_t *)((uint8_t *)eth_hdr + sizeof(cord_eth_hdr_t));
}

cord_ipv6_hdr_t* cord_header_ipv6(const void *buffer)
{
    return (cord_ipv6_hdr_t *)buffer;
}

cord_ipv6_hdr_t* cord_header_ipv6_from_eth(const cord_eth_hdr_t *eth_hdr)
{
    if (cord_ntohs(eth_hdr->h_proto) != CORD_ETH_P_IPV6) {
        return NULL;
    }
    return (cord_ipv6_hdr_t *)((uint8_t *)eth_hdr + sizeof(cord_eth_hdr_t));
}

cord_icmp_hdr_t* cord_header_icmp(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_ICMP) {
        return NULL;
    }
    return (cord_icmp_hdr_t *)((uint8_t *)ip_hdr + (ip_hdr->ihl * 4));
}

cord_icmpv6_hdr_t* cord_header_icmpv6(const cord_ipv6_hdr_t *ip6_hdr)
{
    if (ip6_hdr->nexthdr != CORD_IPPROTO_ICMPV6) {
        return NULL;
    }
    return (cord_icmpv6_hdr_t *)((uint8_t *)ip6_hdr + sizeof(cord_ipv6_hdr_t));
}

// Layer 4 Protocol Headers
cord_tcp_hdr_t* cord_header_tcp_ipv4(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_TCP) {
        return NULL;
    }
    return (cord_tcp_hdr_t *)((uint8_t *)ip_hdr + (ip_hdr->ihl * 4));
}

cord_tcp_hdr_t* cord_header_tcp_ipv6(const cord_ipv6_hdr_t *ip6_hdr)
{
    if (ip6_hdr->nexthdr != CORD_IPPROTO_TCP) {
        return NULL;
    }
    return (cord_tcp_hdr_t *)((uint8_t *)ip6_hdr + sizeof(cord_ipv6_hdr_t));
}

cord_udp_hdr_t* cord_header_udp_ipv4(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_UDP) {
        return NULL;
    }
    return (cord_udp_hdr_t *)((uint8_t *)ip_hdr + (ip_hdr->ihl * 4));
}

cord_udp_hdr_t* cord_header_udp_ipv6(const cord_ipv6_hdr_t *ip6_hdr)
{
    if (ip6_hdr->nexthdr != CORD_IPPROTO_UDP) {
        return NULL;
    }
    return (cord_udp_hdr_t *)((uint8_t *)ip6_hdr + sizeof(cord_ipv6_hdr_t));
}

cord_sctp_hdr_t* cord_header_sctp_ipv4(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_SCTP) {
        return NULL;
    }
    return (cord_sctp_hdr_t *)((uint8_t *)ip_hdr + (ip_hdr->ihl * 4));
}

cord_sctp_hdr_t* cord_header_sctp_ipv6(const cord_ipv6_hdr_t *ip6_hdr)
{
    if (ip6_hdr->nexthdr != CORD_IPPROTO_SCTP) {
        return NULL;
    }
    return (cord_sctp_hdr_t *)((uint8_t *)ip6_hdr + sizeof(cord_ipv6_hdr_t));
}

// Tunneling Protocol Headers
cord_gre_hdr_t* cord_header_gre(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_GRE) {
        return NULL;
    }
    return (cord_gre_hdr_t *)((uint8_t *)ip_hdr + (ip_hdr->ihl * 4));
}

cord_vxlan_hdr_t* cord_header_vxlan(const cord_udp_hdr_t *udp_hdr)
{
    // VXLAN typically uses port 4789
    if (cord_ntohs(udp_hdr->dest) != 4789) {
        return NULL;
    }
    return (cord_vxlan_hdr_t *)((uint8_t *)udp_hdr + sizeof(cord_udp_hdr_t));
}

cord_gtpu_hdr_t* cord_header_gtpu(const cord_udp_hdr_t *udp_hdr)
{
    // GTP-U uses port 2152
    if (cord_ntohs(udp_hdr->dest) != 2152) {
        return NULL;
    }
    return (cord_gtpu_hdr_t *)((uint8_t *)udp_hdr + sizeof(cord_udp_hdr_t));
}

// Routing Protocol Headers
cord_ospf_hdr_t* cord_header_ospf(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_OSPF) {
        return NULL;
    }
    return (cord_ospf_hdr_t *)((uint8_t *)ip_hdr + (ip_hdr->ihl * 4));
}

cord_bgp_hdr_t* cord_header_bgp(const cord_tcp_hdr_t *tcp_hdr)
{
    uint16_t src_port = cord_ntohs(tcp_hdr->source);
    uint16_t dst_port = cord_ntohs(tcp_hdr->dest);
    // BGP uses port 179
    if (src_port != 179 && dst_port != 179) {
        return NULL;
    }
    return (cord_bgp_hdr_t *)((uint8_t *)tcp_hdr + (tcp_hdr->doff * 4));
}

// OSPF Protocol Functions
cord_ospf_hello_t* cord_header_ospf_hello(const cord_ospf_hdr_t *ospf_hdr)
{
    if (ospf_hdr->type != CORD_OSPF_TYPE_HELLO) {
        return NULL;
    }
    return (cord_ospf_hello_t *)ospf_hdr;
}

cord_ospf_db_desc_t* cord_header_ospf_db_desc(const cord_ospf_hdr_t *ospf_hdr)
{
    if (ospf_hdr->type != CORD_OSPF_TYPE_DB_DESC) {
        return NULL;
    }
    return (cord_ospf_db_desc_t *)ospf_hdr;
}

cord_ospf_ls_req_t* cord_header_ospf_ls_req(const cord_ospf_hdr_t *ospf_hdr)
{
    if (ospf_hdr->type != CORD_OSPF_TYPE_LS_REQ) {
        return NULL;
    }
    return (cord_ospf_ls_req_t *)ospf_hdr;
}

cord_ospf_ls_upd_t* cord_header_ospf_ls_upd(const cord_ospf_hdr_t *ospf_hdr)
{
    if (ospf_hdr->type != CORD_OSPF_TYPE_LS_UPD) {
        return NULL;
    }
    return (cord_ospf_ls_upd_t *)ospf_hdr;
}

cord_ospf_ls_ack_t* cord_header_ospf_ls_ack(const cord_ospf_hdr_t *ospf_hdr)
{
    if (ospf_hdr->type != CORD_OSPF_TYPE_LS_ACK) {
        return NULL;
    }
    return (cord_ospf_ls_ack_t *)ospf_hdr;
}

cord_ospf_lsa_hdr_t* cord_header_ospf_lsa(const void *lsa_data)
{
    return (cord_ospf_lsa_hdr_t *)lsa_data;
}

cord_ospf_router_lsa_t* cord_header_ospf_router_lsa(const cord_ospf_lsa_hdr_t *lsa_hdr)
{
    if (lsa_hdr->ls_type != CORD_OSPF_LSA_ROUTER) {
        return NULL;
    }
    return (cord_ospf_router_lsa_t *)lsa_hdr;
}

cord_ospf_network_lsa_t* cord_header_ospf_network_lsa(const cord_ospf_lsa_hdr_t *lsa_hdr)
{
    if (lsa_hdr->ls_type != CORD_OSPF_LSA_NETWORK) {
        return NULL;
    }
    return (cord_ospf_network_lsa_t *)lsa_hdr;
}

cord_ospf_summary_lsa_t* cord_header_ospf_summary_lsa(const cord_ospf_lsa_hdr_t *lsa_hdr)
{
    if (lsa_hdr->ls_type != CORD_OSPF_LSA_SUMMARY_NET &&
        lsa_hdr->ls_type != CORD_OSPF_LSA_SUMMARY_ASBR) {
        return NULL;
    }
    return (cord_ospf_summary_lsa_t *)lsa_hdr;
}

cord_ospf_external_lsa_t* cord_header_ospf_external_lsa(const cord_ospf_lsa_hdr_t *lsa_hdr)
{
    if (lsa_hdr->ls_type != CORD_OSPF_LSA_EXTERNAL) {
        return NULL;
    }
    return (cord_ospf_external_lsa_t *)lsa_hdr;
}

cord_ospf_nssa_lsa_t* cord_header_ospf_nssa_lsa(const cord_ospf_lsa_hdr_t *lsa_hdr)
{
    if (lsa_hdr->ls_type != CORD_OSPF_LSA_NSSA) {
        return NULL;
    }
    return (cord_ospf_nssa_lsa_t *)lsa_hdr;
}

cord_ospf_opaque_lsa_t* cord_header_ospf_opaque_lsa(const cord_ospf_lsa_hdr_t *lsa_hdr)
{
    if (lsa_hdr->ls_type != CORD_OSPF_LSA_LINK_LOCAL &&
        lsa_hdr->ls_type != CORD_OSPF_LSA_AREA_LOCAL &&
        lsa_hdr->ls_type != CORD_OSPF_LSA_AS_EXTERNAL) {
        return NULL;
    }
    return (cord_ospf_opaque_lsa_t *)lsa_hdr;
}

// BGP Protocol Functions
cord_bgp_open_t* cord_header_bgp_open(const cord_bgp_hdr_t *bgp_hdr)
{
    if (bgp_hdr->type != CORD_BGP_TYPE_OPEN) {
        return NULL;
    }
    return (cord_bgp_open_t *)bgp_hdr;
}

cord_bgp_update_t* cord_header_bgp_update(const cord_bgp_hdr_t *bgp_hdr)
{
    if (bgp_hdr->type != CORD_BGP_TYPE_UPDATE) {
        return NULL;
    }
    return (cord_bgp_update_t *)bgp_hdr;
}

cord_bgp_notification_t* cord_header_bgp_notification(const cord_bgp_hdr_t *bgp_hdr)
{
    if (bgp_hdr->type != CORD_BGP_TYPE_NOTIFICATION) {
        return NULL;
    }
    return (cord_bgp_notification_t *)bgp_hdr;
}

cord_bgp_keepalive_t* cord_header_bgp_keepalive(const cord_bgp_hdr_t *bgp_hdr)
{
    if (bgp_hdr->type != CORD_BGP_TYPE_KEEPALIVE) {
        return NULL;
    }
    return (cord_bgp_keepalive_t *)bgp_hdr;
}

cord_bgp_path_attr_t* cord_header_bgp_path_attr(const void *attr_data)
{
    return (cord_bgp_path_attr_t *)attr_data;
}

cord_bgp_origin_attr_t* cord_header_bgp_origin_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_ORIGIN) {
        return NULL;
    }
    return (cord_bgp_origin_attr_t *)attr;
}

cord_bgp_as_path_attr_t* cord_header_bgp_as_path_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_AS_PATH) {
        return NULL;
    }
    return (cord_bgp_as_path_attr_t *)attr;
}

cord_bgp_next_hop_attr_t* cord_header_bgp_next_hop_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_NEXT_HOP) {
        return NULL;
    }
    return (cord_bgp_next_hop_attr_t *)attr;
}

cord_bgp_med_attr_t* cord_header_bgp_med_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_MED) {
        return NULL;
    }
    return (cord_bgp_med_attr_t *)attr;
}

cord_bgp_local_pref_attr_t* cord_header_bgp_local_pref_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_LOCAL_PREF) {
        return NULL;
    }
    return (cord_bgp_local_pref_attr_t *)attr;
}

cord_bgp_communities_attr_t* cord_header_bgp_communities_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_COMMUNITIES) {
        return NULL;
    }
    return (cord_bgp_communities_attr_t *)attr;
}

cord_bgp_mp_reach_attr_t* cord_header_bgp_mp_reach_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_MP_REACH_NLRI) {
        return NULL;
    }
    return (cord_bgp_mp_reach_attr_t *)attr;
}

cord_bgp_mp_unreach_attr_t* cord_header_bgp_mp_unreach_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_MP_UNREACH_NLRI) {
        return NULL;
    }
    return (cord_bgp_mp_unreach_attr_t *)attr;
}

cord_bgp_extended_communities_attr_t* cord_header_bgp_extended_communities_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_EXT_COMMUNITIES) {
        return NULL;
    }
    return (cord_bgp_extended_communities_attr_t *)attr;
}

cord_bgp_large_communities_attr_t* cord_header_bgp_large_communities_attr(const cord_bgp_path_attr_t *attr)
{
    if (attr->type_code != CORD_BGP_ATTR_LARGE_COMM) {
        return NULL;
    }
    return (cord_bgp_large_communities_attr_t *)attr;
}

// RIP Protocol Functions
cord_rip_hdr_t* cord_header_rip(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t src_port = cord_ntohs(udp_hdr->source);
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    // RIP uses port 520
    if (src_port != CORD_PORT_RIP && dst_port != CORD_PORT_RIP) {
        return NULL;
    }
    return (cord_rip_hdr_t *)((uint8_t *)udp_hdr + sizeof(cord_udp_hdr_t));
}

cord_rip_msg_t* cord_header_rip_msg(const cord_udp_hdr_t *udp_hdr)
{
    return (cord_rip_msg_t *)cord_header_rip(udp_hdr);
}

cord_rip_v1_entry_t* cord_header_rip_v1_entry(const cord_rip_msg_t *rip_msg, uint16_t index)
{
    if (!rip_msg || rip_msg->hdr.version != CORD_RIP_VERSION_1) {
        return NULL;
    }
    return (cord_rip_v1_entry_t *)((uint8_t *)rip_msg + sizeof(cord_rip_hdr_t) +
                                  (index * sizeof(cord_rip_v1_entry_t)));
}

cord_rip_v2_entry_t* cord_header_rip_v2_entry(const cord_rip_msg_t *rip_msg, uint16_t index)
{
    if (!rip_msg || rip_msg->hdr.version != CORD_RIP_VERSION_2) {
        return NULL;
    }
    return (cord_rip_v2_entry_t *)((uint8_t *)rip_msg + sizeof(cord_rip_hdr_t) +
                                  (index * sizeof(cord_rip_v2_entry_t)));
}

cord_rip_v2_auth_t* cord_header_rip_v2_auth(const cord_rip_msg_t *rip_msg, uint16_t index)
{
    if (!rip_msg || rip_msg->hdr.version != CORD_RIP_VERSION_2) {
        return NULL;
    }
    cord_rip_v2_auth_t *auth = (cord_rip_v2_auth_t *)((uint8_t *)rip_msg + sizeof(cord_rip_hdr_t) +
                                                     (index * sizeof(cord_rip_v2_auth_t)));
    // Check if this is actually an authentication entry
    if (cord_ntohs(auth->address_family) != CORD_RIP_AF_AUTH) {
        return NULL;
    }
    return auth;
}

cord_ripng_hdr_t* cord_header_ripng(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t src_port = cord_ntohs(udp_hdr->source);
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    // RIPng uses port 521
    if (src_port != CORD_PORT_RIPNG && dst_port != CORD_PORT_RIPNG) {
        return NULL;
    }
    return (cord_ripng_hdr_t *)((uint8_t *)udp_hdr + sizeof(cord_udp_hdr_t));
}

cord_ripng_entry_t* cord_header_ripng_entry(const cord_ripng_hdr_t *ripng_hdr, uint16_t index)
{
    if (!ripng_hdr || ripng_hdr->version != CORD_RIPNG_VERSION) {
        return NULL;
    }
    return (cord_ripng_entry_t *)((uint8_t *)ripng_hdr + sizeof(cord_ripng_hdr_t) +
                                 (index * sizeof(cord_ripng_entry_t)));
}

// IS-IS Protocol Functions
cord_isis_common_hdr_t* cord_header_isis_common(const void *buffer)
{
    cord_isis_common_hdr_t *hdr = (cord_isis_common_hdr_t *)buffer;
    // Verify IS-IS protocol discriminator
    if (hdr->irpd != CORD_ISIS_PROTO_DISCRIMINATOR) {
        return NULL;
    }
    return hdr;
}

cord_isis_p2p_hello_t* cord_header_isis_p2p_hello(const cord_isis_common_hdr_t *common_hdr)
{
    if (common_hdr->pdu_type != CORD_ISIS_PDU_PTP_IIH) {
        return NULL;
    }
    return (cord_isis_p2p_hello_t *)common_hdr;
}

cord_isis_lan_hello_t* cord_header_isis_lan_hello(const cord_isis_common_hdr_t *common_hdr)
{
    if (common_hdr->pdu_type != CORD_ISIS_PDU_L1_LAN_IIH &&
        common_hdr->pdu_type != CORD_ISIS_PDU_L2_LAN_IIH) {
        return NULL;
    }
    return (cord_isis_lan_hello_t *)common_hdr;
}

cord_isis_lsp_t* cord_header_isis_lsp(const cord_isis_common_hdr_t *common_hdr)
{
    if (common_hdr->pdu_type != CORD_ISIS_PDU_L1_LSP &&
        common_hdr->pdu_type != CORD_ISIS_PDU_L2_LSP) {
        return NULL;
    }
    return (cord_isis_lsp_t *)common_hdr;
}

cord_isis_csnp_t* cord_header_isis_csnp(const cord_isis_common_hdr_t *common_hdr)
{
    if (common_hdr->pdu_type != CORD_ISIS_PDU_L1_CSNP &&
        common_hdr->pdu_type != CORD_ISIS_PDU_L2_CSNP) {
        return NULL;
    }
    return (cord_isis_csnp_t *)common_hdr;
}

cord_isis_psnp_t* cord_header_isis_psnp(const cord_isis_common_hdr_t *common_hdr)
{
    if (common_hdr->pdu_type != CORD_ISIS_PDU_L1_PSNP &&
        common_hdr->pdu_type != CORD_ISIS_PDU_L2_PSNP) {
        return NULL;
    }
    return (cord_isis_psnp_t *)common_hdr;
}

cord_isis_tlv_t* cord_header_isis_tlv(const void *tlv_data)
{
    return (cord_isis_tlv_t *)tlv_data;
}

cord_isis_area_addr_tlv_t* cord_header_isis_area_addr_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_AREA_ADDR) {
        return NULL;
    }
    return (cord_isis_area_addr_tlv_t *)tlv;
}

cord_isis_iis_neighbors_tlv_t* cord_header_isis_iis_neighbors_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_IIS_NEIGHBORS) {
        return NULL;
    }
    return (cord_isis_iis_neighbors_tlv_t *)tlv;
}

cord_isis_auth_tlv_t* cord_header_isis_auth_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_AUTHENTICATION) {
        return NULL;
    }
    return (cord_isis_auth_tlv_t *)tlv;
}

cord_isis_lsp_entries_tlv_t* cord_header_isis_lsp_entries_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_LSP_ENTRIES) {
        return NULL;
    }
    return (cord_isis_lsp_entries_tlv_t *)tlv;
}

cord_isis_extended_is_reach_tlv_t* cord_header_isis_extended_is_reach_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_EXTENDED_IS_REACH) {
        return NULL;
    }
    return (cord_isis_extended_is_reach_tlv_t *)tlv;
}

cord_isis_ip_internal_reach_tlv_t* cord_header_isis_ip_internal_reach_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_IP_INTERNAL_REACH) {
        return NULL;
    }
    return (cord_isis_ip_internal_reach_tlv_t *)tlv;
}

cord_isis_ip_external_reach_tlv_t* cord_header_isis_ip_external_reach_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_IP_EXTERNAL_REACH) {
        return NULL;
    }
    return (cord_isis_ip_external_reach_tlv_t *)tlv;
}

cord_isis_extended_ip_reach_tlv_t* cord_header_isis_extended_ip_reach_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_EXTENDED_IP_REACH) {
        return NULL;
    }
    return (cord_isis_extended_ip_reach_tlv_t *)tlv;
}

cord_isis_ipv6_reach_tlv_t* cord_header_isis_ipv6_reach_tlv(const cord_isis_tlv_t *tlv)
{
    if (tlv->type != CORD_ISIS_TLV_IPV6_REACH) {
        return NULL;
    }
    return (cord_isis_ipv6_reach_tlv_t *)tlv;
}

// EIGRP Protocol Functions
cord_eigrp_hdr_t* cord_header_eigrp(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_EIGRP) {
        return NULL;
    }
    return (cord_eigrp_hdr_t *)((uint8_t *)ip_hdr + (ip_hdr->ihl * 4));
}

cord_eigrp_tlv_t* cord_header_eigrp_tlv(const void *tlv_data)
{
    return (cord_eigrp_tlv_t *)tlv_data;
}

// PIM Protocol Functions
cord_pim_hdr_t* cord_header_pim(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_PORT_PIM) {
        return NULL;
    }
    return (cord_pim_hdr_t *)((uint8_t *)ip_hdr + (ip_hdr->ihl * 4));
}

// First Hop Redundancy Protocol Functions
cord_hsrp_hdr_t* cord_header_hsrp(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t src_port = cord_ntohs(udp_hdr->source);
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    // HSRP uses port 1985
    if (src_port != CORD_PORT_HSRP && dst_port != CORD_PORT_HSRP) {
        return NULL;
    }
    return (cord_hsrp_hdr_t *)((uint8_t *)udp_hdr + sizeof(cord_udp_hdr_t));
}

cord_vrrp_hdr_t* cord_header_vrrp(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_PORT_VRRP) {
        return NULL;
    }
    return (cord_vrrp_hdr_t *)((uint8_t *)ip_hdr + (ip_hdr->ihl * 4));
}

// Network Management Protocol Functions
cord_bfd_hdr_t* cord_header_bfd(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t src_port = cord_ntohs(udp_hdr->source);
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    // BFD uses ports 3784 (control) or 3785 (echo)
    if ((src_port != CORD_PORT_BFD_CONTROL && src_port != CORD_PORT_BFD_ECHO) &&
        (dst_port != CORD_PORT_BFD_CONTROL && dst_port != CORD_PORT_BFD_ECHO)) {
        return NULL;
    }
    return (cord_bfd_hdr_t *)((uint8_t *)udp_hdr + sizeof(cord_udp_hdr_t));
}

cord_ldp_hdr_t* cord_header_ldp(const cord_tcp_hdr_t *tcp_hdr)
{
    uint16_t src_port = cord_ntohs(tcp_hdr->source);
    uint16_t dst_port = cord_ntohs(tcp_hdr->dest);
    // LDP uses port 646
    if (src_port != CORD_PORT_LDP && dst_port != CORD_PORT_LDP) {
        return NULL;
    }
    return (cord_ldp_hdr_t *)((uint8_t *)tcp_hdr + (tcp_hdr->doff * 4));
}

cord_rsvp_hdr_t* cord_header_rsvp(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_PORT_RSVP) {
        return NULL;
    }
    return (cord_rsvp_hdr_t *)((uint8_t *)ip_hdr + (ip_hdr->ihl * 4));
}

// IGMP Protocol Functions
cord_igmpv3_query_t* cord_header_igmpv3_query(const cord_ipv4_hdr_t *ip_hdr)
{
    if (ip_hdr->protocol != CORD_IPPROTO_IGMP) {
        return NULL;
    }
    cord_igmpv3_query_t *igmp = (cord_igmpv3_query_t *)((uint8_t *)ip_hdr + (ip_hdr->ihl * 4));
    // Check if this is an IGMPv3 query
    if (igmp->type != CORD_IGMP_TYPE_MEMBERSHIP_QUERY) {
        return NULL;
    }
    return igmp;
}

// DHCP Protocol Functions
cord_dhcp_hdr_t* cord_header_dhcp(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t src_port = cord_ntohs(udp_hdr->source);
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    // DHCP uses ports 67 (server) or 68 (client)
    if ((src_port != CORD_PORT_DHCP_SERVER && src_port != CORD_PORT_DHCP_CLIENT) &&
        (dst_port != CORD_PORT_DHCP_SERVER && dst_port != CORD_PORT_DHCP_CLIENT)) {
        return NULL;
    }
    cord_dhcp_hdr_t *dhcp = (cord_dhcp_hdr_t *)((uint8_t *)udp_hdr + sizeof(cord_udp_hdr_t));
    // Verify DHCP magic cookie
    if (cord_ntohl(dhcp->magic) != CORD_DHCP_MAGIC_COOKIE) {
        return NULL;
    }
    return dhcp;
}

cord_dhcp_option_t* cord_header_dhcp_option(const cord_dhcp_hdr_t *dhcp_hdr, uint16_t offset)
{
    if (!dhcp_hdr) {
        return NULL;
    }
    return (cord_dhcp_option_t *)((uint8_t *)dhcp_hdr->options + offset);
}

cord_dhcpv6_hdr_t* cord_header_dhcpv6(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t src_port = cord_ntohs(udp_hdr->source);
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    // DHCPv6 uses ports 546 (client) or 547 (server)
    if ((src_port != CORD_PORT_DHCPV6_SERVER && src_port != CORD_PORT_DHCPV6_CLIENT) &&
        (dst_port != CORD_PORT_DHCPV6_SERVER && dst_port != CORD_PORT_DHCPV6_CLIENT)) {
        return NULL;
    }
    cord_dhcpv6_hdr_t *dhcpv6 = (cord_dhcpv6_hdr_t *)((uint8_t *)udp_hdr + sizeof(cord_udp_hdr_t));
    // Check if it's a relay message (types 12 or 13)
    if (dhcpv6->msg_type == CORD_DHCPV6_RELAY_FORW || dhcpv6->msg_type == CORD_DHCPV6_RELAY_REPL) {
        return NULL; // Use cord_header_dhcpv6_relay() for relay messages
    }
    return dhcpv6;
}

cord_dhcpv6_relay_hdr_t* cord_header_dhcpv6_relay(const cord_udp_hdr_t *udp_hdr)
{
    uint16_t src_port = cord_ntohs(udp_hdr->source);
    uint16_t dst_port = cord_ntohs(udp_hdr->dest);
    // DHCPv6 uses ports 546 (client) or 547 (server)
    if ((src_port != CORD_PORT_DHCPV6_SERVER && src_port != CORD_PORT_DHCPV6_CLIENT) &&
        (dst_port != CORD_PORT_DHCPV6_SERVER && dst_port != CORD_PORT_DHCPV6_CLIENT)) {
        return NULL;
    }
    cord_dhcpv6_relay_hdr_t *relay = (cord_dhcpv6_relay_hdr_t *)((uint8_t *)udp_hdr + sizeof(cord_udp_hdr_t));
    // Check if it's a relay message (types 12 or 13)
    if (relay->msg_type != CORD_DHCPV6_RELAY_FORW && relay->msg_type != CORD_DHCPV6_RELAY_REPL) {
        return NULL;
    }
    return relay;
}

cord_dhcpv6_option_t* cord_header_dhcpv6_option(const void *options_data, uint16_t offset)
{
    if (!options_data) {
        return NULL;
    }
    return (cord_dhcpv6_option_t *)((uint8_t *)options_data + offset);
}

// IPv6 Neighbor Discovery Protocol Functions
cord_ipv6_nd_router_solicit_t* cord_header_ipv6_nd_router_solicit(const cord_icmpv6_hdr_t *icmp6_hdr)
{
    if (icmp6_hdr->type != CORD_ICMPV6_ND_ROUTER_SOLICIT) {
        return NULL;
    }
    return (cord_ipv6_nd_router_solicit_t *)icmp6_hdr;
}

cord_ipv6_nd_router_advert_t* cord_header_ipv6_nd_router_advert(const cord_icmpv6_hdr_t *icmp6_hdr)
{
    if (icmp6_hdr->type != CORD_ICMPV6_ND_ROUTER_ADVERT) {
        return NULL;
    }
    return (cord_ipv6_nd_router_advert_t *)icmp6_hdr;
}

cord_ipv6_nd_neighbor_solicit_t* cord_header_ipv6_nd_neighbor_solicit(const cord_icmpv6_hdr_t *icmp6_hdr)
{
    if (icmp6_hdr->type != CORD_ICMPV6_ND_NEIGHBOR_SOLICIT) {
        return NULL;
    }
    return (cord_ipv6_nd_neighbor_solicit_t *)icmp6_hdr;
}

cord_ipv6_nd_neighbor_advert_t* cord_header_ipv6_nd_neighbor_advert(const cord_icmpv6_hdr_t *icmp6_hdr)
{
    if (icmp6_hdr->type != CORD_ICMPV6_ND_NEIGHBOR_ADVERT) {
        return NULL;
    }
    return (cord_ipv6_nd_neighbor_advert_t *)icmp6_hdr;
}

cord_ipv6_nd_redirect_t* cord_header_ipv6_nd_redirect(const cord_icmpv6_hdr_t *icmp6_hdr)
{
    if (icmp6_hdr->type != CORD_ICMPV6_ND_REDIRECT) {
        return NULL;
    }
    return (cord_ipv6_nd_redirect_t *)icmp6_hdr;
}

cord_ipv6_nd_opt_t* cord_header_ipv6_nd_option(const void *options_data, uint16_t offset)
{
    if (!options_data) {
        return NULL;
    }
    return (cord_ipv6_nd_opt_t *)((uint8_t *)options_data + offset);
}

cord_ipv6_nd_opt_lladdr_t* cord_header_ipv6_nd_opt_lladdr(const cord_ipv6_nd_opt_t *opt)
{
    if (!opt || (opt->type != CORD_IPV6_ND_OPT_SOURCE_LLADDR && opt->type != CORD_IPV6_ND_OPT_TARGET_LLADDR)) {
        return NULL;
    }
    return (cord_ipv6_nd_opt_lladdr_t *)opt;
}

cord_ipv6_nd_opt_prefix_info_t* cord_header_ipv6_nd_opt_prefix_info(const cord_ipv6_nd_opt_t *opt)
{
    if (!opt || opt->type != CORD_IPV6_ND_OPT_PREFIX_INFO) {
        return NULL;
    }
    return (cord_ipv6_nd_opt_prefix_info_t *)opt;
}

cord_ipv6_nd_opt_mtu_t* cord_header_ipv6_nd_opt_mtu(const cord_ipv6_nd_opt_t *opt)
{
    if (!opt || opt->type != CORD_IPV6_ND_OPT_MTU) {
        return NULL;
    }
    return (cord_ipv6_nd_opt_mtu_t *)opt;
}

cord_ipv6_nd_opt_rdnss_t* cord_header_ipv6_nd_opt_rdnss(const cord_ipv6_nd_opt_t *opt)
{
    if (!opt || opt->type != CORD_IPV6_ND_OPT_RDNSS) {
        return NULL;
    }
    return (cord_ipv6_nd_opt_rdnss_t *)opt;
}

cord_ipv6_nd_opt_dnssl_t* cord_header_ipv6_nd_opt_dnssl(const cord_ipv6_nd_opt_t *opt)
{
    if (!opt || opt->type != CORD_IPV6_ND_OPT_DNSSL) {
        return NULL;
    }
    return (cord_ipv6_nd_opt_dnssl_t *)opt;
}

// Ethernet Field Getters
void cord_get_field_eth_dst_addr(const cord_eth_hdr_t *eth, cord_mac_addr_t *dst)
{
    *dst = eth->h_dest;
}

void cord_get_field_eth_src_addr(const cord_eth_hdr_t *eth, cord_mac_addr_t *src)
{
    *src = eth->h_source;
}

uint16_t cord_get_field_eth_type(const cord_eth_hdr_t *eth)
{
    return eth->h_proto;
}

uint16_t cord_get_field_eth_type_ntohs(const cord_eth_hdr_t *eth)
{
    return cord_ntohs(eth->h_proto);
}

// VLAN Field Getters
uint16_t cord_get_field_vlan_tci(const cord_vlan_hdr_t *vlan)
{
    return vlan->tci;
}

uint16_t cord_get_field_vlan_tci_ntohs(const cord_vlan_hdr_t *vlan)
{
    return cord_ntohs(vlan->tci);
}

uint8_t cord_get_field_vlan_pcp(const cord_vlan_hdr_t *vlan)
{
    return (vlan->tci >> 13) & 0x07;
}

uint8_t cord_get_field_vlan_pcp_ntohs(const cord_vlan_hdr_t *vlan)
{
    uint16_t tci_host = cord_ntohs(vlan->tci);
    return (tci_host >> 13) & 0x07;
}

uint8_t cord_get_field_vlan_dei(const cord_vlan_hdr_t *vlan)
{
    return (vlan->tci >> 12) & 0x01;
}

uint8_t cord_get_field_vlan_dei_ntohs(const cord_vlan_hdr_t *vlan)
{
    uint16_t tci_host = cord_ntohs(vlan->tci);
    return (tci_host >> 12) & 0x01;
}

uint16_t cord_get_field_vlan_vid(const cord_vlan_hdr_t *vlan)
{
    return vlan->tci & 0x0FFF;
}

uint16_t cord_get_field_vlan_vid_ntohs(const cord_vlan_hdr_t *vlan)
{
    uint16_t tci_host = cord_ntohs(vlan->tci);
    return tci_host & 0x0FFF;
}

uint16_t cord_get_field_vlan_type(const cord_vlan_hdr_t *vlan)
{
    return vlan->h_proto;
}

uint16_t cord_get_field_vlan_type_ntohs(const cord_vlan_hdr_t *vlan)
{
    return cord_ntohs(vlan->h_proto);
}

// IPv4 Field Getters
uint8_t cord_get_field_ipv4_version(const cord_ipv4_hdr_t *ip)
{
    return ip->version;
}

uint8_t cord_get_field_ipv4_ihl(const cord_ipv4_hdr_t *ip)
{
    return ip->ihl;
}

uint8_t cord_get_field_ipv4_tos(const cord_ipv4_hdr_t *ip)
{
    return ip->tos;
}

uint8_t cord_get_field_ipv4_dscp(const cord_ipv4_hdr_t *ip)
{
    return (ip->tos >> 2) & 0x3F;
}

uint8_t cord_get_field_ipv4_ecn(const cord_ipv4_hdr_t *ip)
{
    return ip->tos & 0x03;
}

uint16_t cord_get_field_ipv4_total_length(const cord_ipv4_hdr_t *ip)
{
    return ip->tot_len;
}

uint16_t cord_get_field_ipv4_total_length_ntohs(const cord_ipv4_hdr_t *ip)
{
    return cord_ntohs(ip->tot_len);
}

uint8_t cord_get_field_ipv4_header_length(const cord_ipv4_hdr_t *ip)
{
    return ip->ihl << 2;
}

uint16_t cord_get_field_ipv4_id(const cord_ipv4_hdr_t *ip)
{
    return ip->id;
}

uint16_t cord_get_field_ipv4_id_ntohs(const cord_ipv4_hdr_t *ip)
{
    return cord_ntohs(ip->id);
}

uint16_t cord_get_field_ipv4_frag_off(const cord_ipv4_hdr_t *ip)
{
    return ip->frag_off;
}

uint16_t cord_get_field_ipv4_frag_off_ntohs(const cord_ipv4_hdr_t *ip)
{
    return cord_ntohs(ip->frag_off);
}

uint8_t cord_get_field_ipv4_ttl(const cord_ipv4_hdr_t *ip)
{
    return ip->ttl;
}

uint8_t cord_get_field_ipv4_protocol(const cord_ipv4_hdr_t *ip)
{
    return ip->protocol;
}

uint16_t cord_get_field_ipv4_checksum(const cord_ipv4_hdr_t *ip)
{
    return ip->check;
}

uint16_t cord_get_field_ipv4_checksum_ntohs(const cord_ipv4_hdr_t *ip)
{
    return cord_ntohs(ip->check);
}

uint32_t cord_get_field_ipv4_src_addr(const cord_ipv4_hdr_t *ip)
{
    return ip->saddr.addr;
}

uint32_t cord_get_field_ipv4_src_addr_ntohl(const cord_ipv4_hdr_t *ip)
{
    return cord_ntohl(ip->saddr.addr);
}

uint32_t cord_get_field_ipv4_dst_addr(const cord_ipv4_hdr_t *ip)
{
    return ip->daddr.addr;
}

uint32_t cord_get_field_ipv4_dst_addr_ntohl(const cord_ipv4_hdr_t *ip)
{
    return cord_ntohl(ip->daddr.addr);
}

// IPv6 Field Getters
uint8_t cord_get_field_ipv6_version(const cord_ipv6_hdr_t *ip6)
{
    return ip6->version;
}

uint8_t cord_get_field_ipv6_version_ntohl(const cord_ipv6_hdr_t *ip6)
{
    uint32_t first_word = *(const uint32_t*)ip6;
    uint32_t first_word_host = cord_ntohl(first_word);
    return (first_word_host >> 28) & 0x0F;
}

uint8_t cord_get_field_ipv6_traffic_class(const cord_ipv6_hdr_t *ip6)
{
    return ip6->traffic_class;
}

uint8_t cord_get_field_ipv6_traffic_class_ntohl(const cord_ipv6_hdr_t *ip6)
{
    uint32_t first_word = *(const uint32_t*)ip6;
    uint32_t first_word_host = cord_ntohl(first_word);
    return (first_word_host >> 20) & 0xFF;
}

uint32_t cord_get_field_ipv6_flow_label(const cord_ipv6_hdr_t *ip6)
{
    return ip6->flow_label;
}

uint32_t cord_get_field_ipv6_flow_label_ntohl(const cord_ipv6_hdr_t *ip6)
{
    uint32_t first_word = *(const uint32_t*)ip6;
    uint32_t first_word_host = cord_ntohl(first_word);
    return first_word_host & 0x000FFFFF;
}

uint16_t cord_get_field_ipv6_payload_length(const cord_ipv6_hdr_t *ip6)
{
    return ip6->payload_len;
}

uint16_t cord_get_field_ipv6_payload_length_ntohs(const cord_ipv6_hdr_t *ip6)
{
    return cord_ntohs(ip6->payload_len);
}

uint8_t cord_get_field_ipv6_next_header(const cord_ipv6_hdr_t *ip6)
{
    return ip6->nexthdr;
}

uint8_t cord_get_field_ipv6_hop_limit(const cord_ipv6_hdr_t *ip6)
{
    return ip6->hop_limit;
}

void cord_get_field_ipv6_src_addr(const cord_ipv6_hdr_t *ip6, cord_ipv6_addr_t *src)
{
    *src = ip6->saddr;
}

void cord_get_field_ipv6_dst_addr(const cord_ipv6_hdr_t *ip6, cord_ipv6_addr_t *dst)
{
    *dst = ip6->daddr;
}

// TCP Field Getters
uint16_t cord_get_field_tcp_src_port(const cord_tcp_hdr_t *tcp)
{
    return tcp->source;
}

uint16_t cord_get_field_tcp_src_port_ntohs(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohs(tcp->source);
}

uint16_t cord_get_field_tcp_dst_port(const cord_tcp_hdr_t *tcp)
{
    return tcp->dest;
}

uint16_t cord_get_field_tcp_dst_port_ntohs(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohs(tcp->dest);
}

uint32_t cord_get_field_tcp_seq_num(const cord_tcp_hdr_t *tcp)
{
    return tcp->seq;
}

uint32_t cord_get_field_tcp_seq_num_ntohl(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohl(tcp->seq);
}

uint32_t cord_get_field_tcp_ack_num(const cord_tcp_hdr_t *tcp)
{
    return tcp->ack_seq;
}

uint32_t cord_get_field_tcp_ack_num_ntohl(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohl(tcp->ack_seq);
}

uint8_t cord_get_field_tcp_doff(const cord_tcp_hdr_t *tcp)
{
    return tcp->doff;
}

uint16_t cord_get_field_tcp_window(const cord_tcp_hdr_t *tcp)
{
    return tcp->window;
}

uint16_t cord_get_field_tcp_window_ntohs(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohs(tcp->window);
}

uint16_t cord_get_field_tcp_checksum(const cord_tcp_hdr_t *tcp)
{
    return tcp->check;
}

uint16_t cord_get_field_tcp_checksum_ntohs(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohs(tcp->check);
}

uint16_t cord_get_field_tcp_urgent_ptr(const cord_tcp_hdr_t *tcp)
{
    return tcp->urg_ptr;
}

uint16_t cord_get_field_tcp_urgent_ptr_ntohs(const cord_tcp_hdr_t *tcp)
{
    return cord_ntohs(tcp->urg_ptr);
}

bool cord_get_field_tcp_fin(const cord_tcp_hdr_t *tcp)
{
    return tcp->fin;
}

bool cord_get_field_tcp_syn(const cord_tcp_hdr_t *tcp)
{
    return tcp->syn;
}

bool cord_get_field_tcp_rst(const cord_tcp_hdr_t *tcp)
{
    return tcp->rst;
}

bool cord_get_field_tcp_psh(const cord_tcp_hdr_t *tcp)
{
    return tcp->psh;
}

bool cord_get_field_tcp_ack(const cord_tcp_hdr_t *tcp)
{
    return tcp->ack;
}

bool cord_get_field_tcp_urg(const cord_tcp_hdr_t *tcp)
{
    return tcp->urg;
}

bool cord_get_field_tcp_ece(const cord_tcp_hdr_t *tcp)
{
    return tcp->ece;
}

bool cord_get_field_tcp_cwr(const cord_tcp_hdr_t *tcp)
{
    return tcp->cwr;
}

// UDP Field Getters
uint16_t cord_get_field_udp_src_port(const cord_udp_hdr_t *udp)
{
    return udp->source;
}

uint16_t cord_get_field_udp_src_port_ntohs(const cord_udp_hdr_t *udp)
{
    return cord_ntohs(udp->source);
}

uint16_t cord_get_field_udp_dst_port(const cord_udp_hdr_t *udp)
{
    return udp->dest;
}

uint16_t cord_get_field_udp_dst_port_ntohs(const cord_udp_hdr_t *udp)
{
    return cord_ntohs(udp->dest);
}

uint16_t cord_get_field_udp_length(const cord_udp_hdr_t *udp)
{
    return udp->len;
}

uint16_t cord_get_field_udp_length_ntohs(const cord_udp_hdr_t *udp)
{
    return cord_ntohs(udp->len);
}

uint16_t cord_get_field_udp_checksum(const cord_udp_hdr_t *udp)
{
    return udp->check;
}

uint16_t cord_get_field_udp_checksum_ntohs(const cord_udp_hdr_t *udp)
{
    return cord_ntohs(udp->check);
}

// SCTP Field Getters
uint16_t cord_get_field_sctp_src_port(const cord_sctp_hdr_t *sctp)
{
    return sctp->source;
}

uint16_t cord_get_field_sctp_src_port_ntohs(const cord_sctp_hdr_t *sctp)
{
    return cord_ntohs(sctp->source);
}

uint16_t cord_get_field_sctp_dst_port(const cord_sctp_hdr_t *sctp)
{
    return sctp->dest;
}

uint16_t cord_get_field_sctp_dst_port_ntohs(const cord_sctp_hdr_t *sctp)
{
    return cord_ntohs(sctp->dest);
}

uint32_t cord_get_field_sctp_vtag(const cord_sctp_hdr_t *sctp)
{
    return sctp->vtag;
}

uint32_t cord_get_field_sctp_vtag_ntohl(const cord_sctp_hdr_t *sctp)
{
    return cord_ntohl(sctp->vtag);
}

uint32_t cord_get_field_sctp_checksum(const cord_sctp_hdr_t *sctp)
{
    return sctp->checksum;
}

uint32_t cord_get_field_sctp_checksum_ntohl(const cord_sctp_hdr_t *sctp)
{
    return cord_ntohl(sctp->checksum);
}

// ICMP Field Getters
uint8_t cord_get_field_icmp_type(const cord_icmp_hdr_t *icmp)
{
    return icmp->type;
}

uint8_t cord_get_field_icmp_code(const cord_icmp_hdr_t *icmp)
{
    return icmp->code;
}

uint16_t cord_get_field_icmp_checksum(const cord_icmp_hdr_t *icmp)
{
    return icmp->checksum;
}

uint16_t cord_get_field_icmp_checksum_ntohs(const cord_icmp_hdr_t *icmp)
{
    return cord_ntohs(icmp->checksum);
}

uint16_t cord_get_field_icmp_id(const cord_icmp_hdr_t *icmp)
{
    return icmp->un.echo.id;
}

uint16_t cord_get_field_icmp_id_ntohs(const cord_icmp_hdr_t *icmp)
{
    return cord_ntohs(icmp->un.echo.id);
}

uint16_t cord_get_field_icmp_sequence(const cord_icmp_hdr_t *icmp)
{
    return icmp->un.echo.sequence;
}

uint16_t cord_get_field_icmp_sequence_ntohs(const cord_icmp_hdr_t *icmp)
{
    return cord_ntohs(icmp->un.echo.sequence);
}

//
// From ACTION
//

// IPv4 checksum validation
bool cord_compare_if_ipv4_checksum_valid(const cord_ipv4_hdr_t *ip_hdr)
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

//
// Checksum related
//

// IPv4 payload length calculation
uint16_t cord_calculate_ipv4_payload_length_ntohs(const cord_ipv4_hdr_t *ip_hdr)
{
    uint16_t total_len = cord_ntohs(ip_hdr->tot_len);
    uint8_t hdr_len = ip_hdr->ihl * 4;
    return total_len - hdr_len;
}

// IPv4 checksum calculation
uint16_t cord_calculate_ipv4_checksum(const cord_ipv4_hdr_t *ip_hdr)
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

// TCP checksum calculation for IPv4
uint16_t cord_calculate_tcp_checksum_ipv4(const cord_ipv4_hdr_t *ip_hdr)
{
    // Verify this is a TCP packet
    if (ip_hdr->protocol != CORD_IPPROTO_TCP) {
        return 0; // Invalid protocol
    }
    
    // Calculate IP header length and find TCP header
    uint8_t ip_hdr_len = ip_hdr->ihl * 4;
    const cord_tcp_hdr_t *tcp_hdr = (const cord_tcp_hdr_t*)((const uint8_t*)ip_hdr + ip_hdr_len);
    
    uint32_t sum = 0;
    uint16_t tcp_len = cord_calculate_ipv4_payload_length_ntohs(ip_hdr);
    
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
uint16_t cord_calculate_udp_checksum_ipv4(const cord_ipv4_hdr_t *ip_hdr)
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
uint16_t cord_calculate_icmp_checksum_ipv4(const cord_ipv4_hdr_t *ip_hdr)
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

// Ethernet frame CRC32 calculation
uint32_t cord_calculate_ethernet_crc32(const void *buffer, size_t frame_len)
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