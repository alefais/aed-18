//
// Created by Alessandra Fais
// AED course - MCSN - University of Pisa
// A.A. 2017/18
//

#ifndef AED_LAB05_UTILS_H
#define AED_LAB05_UTILS_H

#include <net/ethernet.h>

/*
 * 802.1Q header structure.
 */
struct vlan_ethhdr {
    u_char h_dest[ETHER_ADDR_LEN];
    u_char h_source[ETHER_ADDR_LEN];
    u_int16_t h_vlan_proto;
    u_int16_t h_vlan_TCI;
    u_int16_t h_vlan_encapsulated_proto;
};

#endif //AED_LAB05_UTILS_H
